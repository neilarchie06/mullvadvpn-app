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

protocol PingerDelegate: AnyObject {
    func pinger(
        _ pinger: Pinger,
        didReceiveResponseFromSender senderAddress: IPv4Address,
        sequenceNumber: UInt16
    )

    func pinger(
        _ pinger: Pinger,
        didFailToReadResponseWithError error: Error
    )
}

final class Pinger {
    typealias EchoReplyHandler = (IPv4Address, UInt16) -> Void

    // Sender identifier passed along with ICMP packet.
    private let identifier: UInt16 = 757

    private var sequenceNumber: UInt16 = 0
    private var socket: CFSocket?

    private let logger = Logger(label: "Pinger")
    private let stateLock = NSRecursiveLock()

    private weak var _delegate: PingerDelegate?

    var delegate: PingerDelegate? {
        get {
            stateLock.lock()
            defer { stateLock.unlock() }

            return _delegate
        }
        set {
            stateLock.lock()
            defer { stateLock.unlock() }

            _delegate = newValue
        }
    }

    deinit {
        closeSocket()
    }

    /// Open socket and optionally bind it to the given interface.
    /// Automatically closes the previously opened socket when called multiple times in a row.
    func openSocket(bindTo interfaceName: String?) throws {
        stateLock.lock()
        defer { stateLock.unlock() }

        closeSocket()

        var context = CFSocketContext()
        context.info = Unmanaged.passUnretained(self).toOpaque()

        guard let newSocket = CFSocketCreate(
            kCFAllocatorDefault,
            AF_INET,
            SOCK_DGRAM,
            IPPROTO_ICMP,
            0,
            { socket, callbackType, address, data, info in
                guard let info = info, callbackType == .readCallBack else {
                    return
                }

                let pinger = Unmanaged<Pinger>.fromOpaque(info).takeUnretainedValue()

                pinger.readSocket()
            },
            &context
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
    /// Returns sequence number on success, otherwise throws a `Pinger.Error`.
    func send(to address: IPv4Address) throws -> UInt16 {
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

        return sequenceNumber
    }

    private func nextSequenceNumber() -> UInt16 {
        stateLock.lock()
        let (partialValue, isOverflow) = sequenceNumber.addingReportingOverflow(1)
        let nextSequenceNumber = isOverflow ? 0 : partialValue

        sequenceNumber = nextSequenceNumber
        stateLock.unlock()

        return nextSequenceNumber
    }

    private func readSocket() {
        let bufferSize = 65535
        var buffer = [UInt8](repeating: 0, count: bufferSize)

        var address = sockaddr()
        var addressLength = socklen_t(MemoryLayout.size(ofValue: address))
        let bytesRead = recvfrom(
            CFSocketGetNative(socket!),
            &buffer,
            bufferSize,
            0,
            &address,
            &addressLength
        )

        do {
            guard bytesRead > 0 else {
                throw Error.receivePacket(errno)
            }

            let senderAddress = try withUnsafeBytes(of: &address) { buffer -> IPv4Address in
                var saddr = buffer.load(as: sockaddr_in.self)
                let addrData = Data(
                    bytes: &saddr.sin_addr.s_addr,
                    count: MemoryLayout<in_addr_t>.size
                )

                guard let ipv4Address = IPv4Address(addrData, nil) else {
                    throw Error.parseIPv4Address
                }

                return ipv4Address
            }

            let ipv4PacketData = Data(bytes: &buffer, count: bytesRead)
            let responseSequence = try validatePacket(ipv4PacketData: ipv4PacketData)

            stateLock.lock()
            _delegate?.pinger(
                self,
                didReceiveResponseFromSender: senderAddress,
                sequenceNumber: responseSequence
            )
            stateLock.unlock()
        } catch {
            stateLock.lock()
            _delegate?.pinger(self, didFailToReadResponseWithError: error)
            stateLock.unlock()
        }
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

    private func getIPv4PacketPayload(data: Data) throws -> Data {
        let minimumPacketSize = MemoryLayout<IPv4Header>.size + MemoryLayout<ICMPHeader>.size
        guard data.count >= minimumPacketSize else {
            throw Error.parseIPv4Packet
        }

        let ipv4Header = data.withUnsafeBytes { $0.load(as: IPv4Header.self) }
        let versionAndHeaderLength = Int(ipv4Header.versionAndHeaderLength)
        let proto = ipv4Header.protocol

        guard (versionAndHeaderLength & 0xF0) == 0x40, proto == IPPROTO_ICMP else {
            throw Error.parseIPv4Packet
        }

        let ipHeaderLength = (versionAndHeaderLength & 0x0F) * MemoryLayout<UInt32>.size

        return data[ipHeaderLength...]
    }

    private func validatePacket(ipv4PacketData: Data) throws -> UInt16 {
        var payload = try getIPv4PacketPayload(data: ipv4PacketData)

        let receivedChecksum = payload.withUnsafeMutableBytes { bufferPointer -> UInt16 in
            let checksum = bufferPointer.load(fromByteOffset: 2, as: UInt16.self)
            bufferPointer.storeBytes(of: UInt16.zero, toByteOffset: 2, as: UInt16.self)
            return checksum
        }

        let computedChecksum = in_chksum(payload)
        guard receivedChecksum == computedChecksum else {
            throw Error.invalidChecksum
        }

        return try payload.withUnsafeBytes { buffer in
            let identifier = buffer.load(fromByteOffset: 4, as: UInt16.self).bigEndian
            let sequenceNumber = buffer.load(fromByteOffset: 6, as: UInt16.self).bigEndian

            guard identifier == self.identifier else {
                throw Error.invalidIdentifier
            }

            return sequenceNumber
        }
    }

    private class func createICMPPacket(
        identifier: UInt16,
        sequenceNumber: UInt16,
        payload: Data?
    ) -> Data {
        let header = ICMPHeader(
            type: UInt8(ICMP_ECHO),
            code: 0,
            checksum: 0,
            identifier: identifier.bigEndian,
            sequenceNumber: sequenceNumber.bigEndian
        )

        var data = withUnsafeBytes(of: header) { Data($0) }
        if let payload = payload {
            data.append(contentsOf: payload)
        }

        let checksum = in_chksum(data)

        // Inject computed checksum into the packet.
        data.withUnsafeMutableBytes { buffer in
            let icmpHeaderPointer = buffer.baseAddress?.assumingMemoryBound(to: ICMPHeader.self)

            icmpHeaderPointer?.pointee.checksum = checksum
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

        /// Failure to receive packet. Contains the `errno`.
        case receivePacket(Int32)

        /// Invalid checksum when matching the echo reply.
        case invalidChecksum

        /// Invalid ICMP identifier.
        case invalidIdentifier

        /// Failure to parse IPv4 packet.
        case parseIPv4Packet

        /// Failure to parse IPv4 address.
        case parseIPv4Address

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
            case let .receivePacket(code):
                return "Failure to receive packet (errno: \(code))."
            case .invalidChecksum:
                return "Invalid checksum."
            case .invalidIdentifier:
                return "Invalid client identifier."
            case .parseIPv4Packet:
                return "Failure to read IPv4 packet."
            case .parseIPv4Address:
                return "Failure to parse IPv4 address."
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
