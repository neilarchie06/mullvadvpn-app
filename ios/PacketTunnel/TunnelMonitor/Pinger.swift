//
//  Pinger.swift
//  PacketTunnel
//
//  Created by pronebird on 21/02/2022.
//  Copyright © 2022 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Logging
import struct Network.IPv4Address

final class Pinger {
    // Sender identifier passed along with ICMP packet.
    private let identifier: UInt16 = 757

    private var sequenceNumber: UInt16 = 0
    private var socket: CFSocket?

    private let logger = Logger(label: "Pinger")
    private let stateLock = NSRecursiveLock()

    deinit {
        closeSocket()
    }

    /// Open socket and optionally bind it to the given interface.
    /// Automatically closes the previously opened socket when called multiple times in a row.
    func openSocket(bindTo interfaceName: String?) throws {
        stateLock.lock()
        defer { stateLock.unlock() }

        closeSocket()

        guard let newSocket = CFSocketCreate(
            kCFAllocatorDefault,
            AF_INET,
            SOCK_DGRAM,
            IPPROTO_ICMP,
            0,
            nil,
            nil
        ) else {
            throw Error.createSocket
        }

        let flags = CFSocketGetSocketFlags(newSocket)
        if (flags & kCFSocketCloseOnInvalidate) == 0 {
            CFSocketSetSocketFlags(newSocket, flags | kCFSocketCloseOnInvalidate)
        }

        if let interfaceName = interfaceName {
            try bindSocket(newSocket, to: interfaceName)
        } else {
            logger.debug("Interface is not specified.")
        }

        guard let runLoop = CFSocketCreateRunLoopSource(kCFAllocatorDefault, newSocket, 0) else {
            throw Error.createRunLoop
        }

        CFRunLoopAddSource(CFRunLoopGetMain(), runLoop, .defaultMode)

        socket = newSocket
    }

    func closeSocket() {
        stateLock.lock()
        defer { stateLock.unlock() }

        if let socket = socket {
            CFSocketInvalidate(socket)

            self.socket = nil
        }
    }

    /// Send ping packet to the given address.
    /// Returns number of bytes sent on success, otherwise -1 on failure.
    func send(to address: IPv4Address) throws -> Int {
        stateLock.lock()
        guard let socket = socket else {
            stateLock.unlock()
            throw Error.closedSocket
        }
        stateLock.unlock()

        var sa = sockaddr_in()
        sa.sin_len = UInt8(MemoryLayout.size(ofValue: sa))
        sa.sin_family = sa_family_t(AF_INET)
        sa.sin_addr = address.rawValue.withUnsafeBytes { buffer in
            return buffer.bindMemory(to: in_addr.self).baseAddress!.pointee
        }

        let sequenceNumber = nextSequenceNumber()
        let packetData = Self.createICMPPacket(
            identifier: identifier,
            sequenceNumber: sequenceNumber,
            payload: nil
        )

        let bytesSent = packetData.withUnsafeBytes { dataBuffer -> Int in
            return withUnsafeBytes(of: &sa) { bufferPointer in
                let sockaddrPointer = bufferPointer.bindMemory(to: sockaddr.self).baseAddress!

                return sendto(
                    CFSocketGetNative(socket),
                    dataBuffer.baseAddress!,
                    dataBuffer.count,
                    0,
                    sockaddrPointer,
                    socklen_t(MemoryLayout<sockaddr_in>.size)
                )
            }
        }

        guard bytesSent != -1 else {
            let errorCode = errno
            logger.debug("Failed to send packet (errno: \(errorCode)).")
            throw Error.sendPacket(errorCode)
        }

        return bytesSent
    }

    private func nextSequenceNumber() -> UInt16 {
        stateLock.lock()
        let (partialValue, isOverflow) = sequenceNumber.addingReportingOverflow(1)
        let nextSequenceNumber = isOverflow ? 0 : partialValue

        sequenceNumber = nextSequenceNumber
        stateLock.unlock()

        return nextSequenceNumber
    }

    private func bindSocket(_ socket: CFSocket, to interfaceName: String) throws {
        var index = if_nametoindex(interfaceName)
        guard index > 0 else {
            throw Error.mapInterfaceNameToIndex(errno)
        }

        logger.debug("Bind socket to \"\(interfaceName)\" (index: \(index))...")

        let result = setsockopt(
            CFSocketGetNative(socket),
            IPPROTO_IP,
            IP_BOUND_IF,
            &index,
            socklen_t(MemoryLayout.size(ofValue: index))
        )

        if result == -1 {
            logger.error(
                "Failed to bind socket to \"\(interfaceName)\" (index: \(index), errno: \(errno))."
            )
            throw Error.bindSocket(errno)
        }
    }

    private class func createICMPPacket(
        identifier: UInt16,
        sequenceNumber: UInt16,
        payload: Data?
    ) -> Data {
        // Create data buffer.
        var data = Data()

        // ICMP type.
        data.append(UInt8(ICMP_ECHO))

        // Code.
        data.append(UInt8(0))

        // Checksum.
        withUnsafeBytes(of: UInt16(0)) { data.append(Data($0)) }

        // Identifier.
        withUnsafeBytes(of: identifier.bigEndian) { data.append(Data($0)) }

        // Sequence number.
        withUnsafeBytes(of: sequenceNumber.bigEndian) { data.append(Data($0)) }

        // Append payload.
        if let payload = payload {
            data.append(contentsOf: payload)
        }

        // Calculate checksum.
        let checksum = in_chksum(data)

        // Inject computed checksum into the packet.
        data.withUnsafeMutableBytes { buffer in
            buffer.storeBytes(of: checksum, toByteOffset: 2, as: UInt16.self)
        }

        return data
    }
}

extension Pinger {
    enum Error: LocalizedError, Equatable {
        /// Failure to create a socket.
        case createSocket

        /// Failure to map interface name to index.
        case mapInterfaceNameToIndex(Int32)

        /// Failure to bind socket to interface.
        case bindSocket(Int32)

        /// Failure to create a runloop for socket.
        case createRunLoop

        /// Failure to send a packet due to socket being closed.
        case closedSocket

        /// Failure to send packet. Contains the `errno`.
        case sendPacket(Int32)

        var errorDescription: String? {
            switch self {
            case .createSocket:
                return "Failure to create socket."
            case .mapInterfaceNameToIndex:
                return "Failure to map interface name to index."
            case .bindSocket:
                return "Failure to bind socket to interface."
            case .createRunLoop:
                return "Failure to create run loop for socket."
            case .closedSocket:
                return "Socket is closed."
            case let .sendPacket(code):
                return "Failure to send packet (errno: \(code))."
            }
        }
    }
}

private func in_chksum(_ data: Data) -> UInt16 {
    let words = sequence(state: data.makeIterator()) { iterator in
        return iterator.next().map { byte in
            return iterator.next().map { nextByte in
                return [byte, nextByte].withUnsafeBytes { buffer in
                    return buffer.load(as: UInt16.self)
                }
            } ?? UInt16(byte)
        }
    }

    let sum = words.reduce(0, &+)

    return ~sum
}
