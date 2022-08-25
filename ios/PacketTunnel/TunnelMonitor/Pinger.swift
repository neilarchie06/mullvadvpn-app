//
//  Pinger.swift
//  PacketTunnel
//
//  Created by pronebird on 21/02/2022.
//  Copyright © 2022 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Logging
import protocol Network.IPAddress
import struct Network.IPv4Address
import struct Network.IPv6Address

protocol PingerDelegate: AnyObject {
    func pinger(
        _ pinger: Pinger,
        didReceiveResponseFromSender senderAddress: IPAddress,
        icmpHeader: ICMPHeader
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
            CFSocketCallBackType.readCallBack.rawValue,
            { socket, callbackType, address, data, info in
                guard let socket = socket, let info = info, callbackType == .readCallBack else {
                    return
                }

                let pinger = Unmanaged<Pinger>.fromOpaque(info).takeUnretainedValue()

                pinger.readSocket(socket)
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
            sequenceNumber: sequenceNumber
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

    private func readSocket(_ socket: CFSocket) {
        let bufferSize = 65535
        var buffer = [UInt8](repeating: 0, count: bufferSize)

        var address = sockaddr()
        var addressLength = socklen_t(MemoryLayout.size(ofValue: address))

        let bytesRead = recvfrom(
            CFSocketGetNative(socket),
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

            guard let icmpHeader = try parseICMPResponse(&buffer[...bytesRead]) else {
                return
            }

            guard let sender = Self.makeIPAddress(from: address) else {
                throw Error.parseIPAddress
            }

            delegate?.pinger(
                self,
                didReceiveResponseFromSender: sender,
                icmpHeader: icmpHeader
            )
        } catch {
            delegate?.pinger(self, didFailToReadResponseWithError: error)
        }
    }

    private func parseICMPResponse(_ ipv4PacketData: inout ArraySlice<UInt8>) throws
        -> ICMPHeader?
    {
        // Check IP packet size.
        guard ipv4PacketData.count >= MemoryLayout<IPv4Header>.size else {
            throw Error.malformedResponse
        }

        // Verify IPv4 header.
        let ipv4Header = ipv4PacketData.withUnsafeBytes { $0.load(as: IPv4Header.self) }
        let payloadLength = ipv4PacketData.count - ipv4Header.headerLength

        guard payloadLength >= MemoryLayout<ICMPHeader>.size, ipv4Header.isIPv4Version else {
            throw Error.malformedResponse
        }
        var payloadData = ipv4PacketData.dropFirst(ipv4Header.headerLength)

        // Parse ICMP header.
        let icmpHeaderPointer = payloadData.withUnsafeMutableBytes { bufferPointer in
            return bufferPointer.baseAddress!.assumingMemoryBound(to: ICMPHeader.self)
        }

        // Check if ICMP response belongs to this process.
        guard icmpHeaderPointer.pointee.identifier.bigEndian == identifier else {
            return nil
        }

        // Verify ICMP type.
        guard icmpHeaderPointer.pointee.type == ICMP_ECHOREPLY else {
            throw Error.malformedResponse
        }

        // Verify ICMP checksum.
        let serverChecksum = icmpHeaderPointer.pointee.checksum
        icmpHeaderPointer.pointee.checksum = 0
        if in_chksum(payloadData) != serverChecksum {
            throw Error.malformedResponse
        }

        var icmpHeader = icmpHeaderPointer.pointee
        icmpHeader.identifier = icmpHeader.identifier.bigEndian
        icmpHeader.sequenceNumber = icmpHeader.sequenceNumber.bigEndian
        icmpHeader.checksum = icmpHeader.checksum.bigEndian
        return icmpHeader
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

    private class func createICMPPacket(identifier: UInt16, sequenceNumber: UInt16) -> Data {
        var header = ICMPHeader(
            type: UInt8(ICMP_ECHO),
            code: 0,
            checksum: 0,
            identifier: identifier.bigEndian,
            sequenceNumber: sequenceNumber.bigEndian
        )
        header.checksum = withUnsafeBytes(of: &header) { in_chksum($0) }

        return withUnsafeBytes(of: &header) { Data($0) }
    }

    private class func makeIPAddress(from sa: sockaddr) -> IPAddress? {
        if sa.sa_family == AF_INET {
            return withUnsafeBytes(of: sa) { buffer -> IPAddress? in
                guard let boundPointer = buffer.bindMemory(to: sockaddr_in.self).baseAddress else {
                    return nil
                }

                var saddr = boundPointer.pointee
                let data = Data(bytes: &saddr.sin_addr, count: MemoryLayout<in_addr>.size)

                return IPv4Address(data, nil)
            }
        }

        if sa.sa_family == AF_INET6 {
            return withUnsafeBytes(of: sa) { buffer in
                guard let boundPointer = buffer.bindMemory(to: sockaddr_in6.self).baseAddress else {
                    return nil
                }
                var saddr6 = boundPointer.pointee
                let data = Data(bytes: &saddr6.sin6_addr, count: MemoryLayout<in6_addr>.size)

                return IPv6Address(data)
            }
        }

        return nil
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

        /// Malformed response.
        case malformedResponse

        /// Failure to parse IP address.
        case parseIPAddress

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
            case .malformedResponse:
                return "Malformed response."
            case .parseIPAddress:
                return "Failed to parse IP address."
            }
        }
    }
}

private func in_chksum<S>(_ data: S) -> UInt16 where S: Sequence, S.Element == UInt8 {
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

private extension IPv4Header {
    /// Returns IPv4 header length.
    var headerLength: Int {
        return Int(versionAndHeaderLength & 0x0F) * MemoryLayout<UInt32>.size
    }

    /// Returns `true` if version header indicates IPv4.
    var isIPv4Version: Bool {
        return (versionAndHeaderLength & 0xF0) == 0x40
    }
}
