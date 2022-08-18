//
//  TunnelMonitor.swift
//  PacketTunnel
//
//  Created by pronebird on 09/02/2022.
//  Copyright © 2022 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Logging
import NetworkExtension
import WireGuardKit

/// Number of seconds to wait between sending ICMP packets.
private let secondsPerPing: TimeInterval = 3

/// Timeout for waiting on receiving traffic after sending the first ICMP packet.
/// The connection is considered lost once this timeout is exceeded.
private let pingTimeout: TimeInterval = 15

/// Timeout for inbound or outbound traffic when monitoring established connection.
private let trafficTimeout: TimeInterval = 120

/// Timeout for waiting on inbound traffic after an increase in outbound traffic is being
/// detected.
private let receiveBytesTimeout: TimeInterval = 5

/// Interval for checking connectivity status.
private let connectivityCheckInterval: TimeInterval = 1

final class TunnelMonitor {
    private var state: State = .stopped

    private let adapter: WireGuardAdapter
    private let internalQueue = DispatchQueue(label: "TunnelMonitor")
    private let delegateQueue: DispatchQueue

    private let pinger = Pinger()
    private var pathMonitor: NWPathMonitor?
    private var timer: DispatchSourceTimer?

    private var probeAddress: IPv4Address?
    private var initialPingTimestamp: Date?
    private var lastPingTimestamp: Date?

    private var logger = Logger(label: "TunnelMonitor")

    private weak var _delegate: TunnelMonitorDelegate?
    weak var delegate: TunnelMonitorDelegate? {
        set {
            internalQueue.sync {
                _delegate = newValue
            }
        }
        get {
            return internalQueue.sync {
                return _delegate
            }
        }
    }

    init(queue: DispatchQueue, adapter: WireGuardAdapter) {
        delegateQueue = queue
        self.adapter = adapter
    }

    deinit {
        stopNoQueue()
    }

    func start(probeAddress: IPv4Address) {
        internalQueue.async {
            self.startNoQueue(probeAddress: probeAddress)
        }
    }

    func stop() {
        internalQueue.async {
            self.stopNoQueue()
        }
    }

    // MARK: - Private

    private func startNoQueue(probeAddress: IPv4Address) {
        if case .stopped = state {
            logger.debug("Start with address: \(probeAddress).")
        } else {
            stopNoQueue(forRestart: true)
            logger.debug("Restart with address: \(probeAddress)")
        }

        self.probeAddress = probeAddress

        let pathMonitor = NWPathMonitor()
        pathMonitor.pathUpdateHandler = { [weak self] path in
            self?.handleNetworkPathUpdate(path)
        }
        pathMonitor.start(queue: internalQueue)
        self.pathMonitor = pathMonitor

        if isNetworkPathReachable(pathMonitor.currentPath) {
            logger.debug("Start monitoring connection.")

            startMonitoring()
        } else {
            logger.debug("Wait for network to become reachable before starting monitoring.")

            state = .waitingConnectivity
        }
    }

    private func stopNoQueue(forRestart: Bool = false) {
        if case .stopped = state {
            return
        }

        if !forRestart {
            logger.debug("Stop tunnel monitor.")
        }

        probeAddress = nil

        pathMonitor?.cancel()
        pathMonitor = nil

        stopMonitoring()

        state = .stopped
    }

    private func checkConnectivity() {
        guard let newStats = getStats() else {
            return
        }

        let now = Date()
        let wasConnecting = state.isConnecting

        /* switch state {
         case let .connected(receiveDate, transmitDate, stats):
             logger
                 .debug(
                     "OLD: RX: \(stats.bytesReceived) TX: \(stats.bytesSent) | NEW: RX: \(newStats.bytesReceived) TX: \(newStats.bytesSent)"
                 )

         case let .connecting(startDate, transmitDate, stats):
             logger
                 .debug(
                     "OLD: RX: \(stats.bytesReceived) TX: \(stats.bytesSent) | NEW: RX: \(newStats.bytesReceived) TX: \(newStats.bytesSent)"
                 )

         default:
             break
         } */

        if state.update(now: now, newStats: newStats) {
            if wasConnecting, state.isConnected {
                sendDelegateConnectionEstablished()
            }

            resetPingStats()
        } else if isPingTimedOut(now: now, timeout: pingTimeout) {
            logger.debug("Ping timeout.")
            resetPingStats()

            stopConnectivityCheckTimer()

            sendDelegateShouldHandleConnectionRecovery { [weak self] in
                guard let self = self else { return }

                self.internalQueue.async {
                    if self.state.isConnecting || self.state.isConnected {
                        self.startConnectivityCheckTimer()
                    }
                }
            }
        } else {
            maybeSendPing(now: now)
        }
    }

    private func handleNetworkPathUpdate(_ networkPath: Network.NWPath) {
        let isReachable = isNetworkPathReachable(networkPath)

        switch (isReachable, state) {
        case (true, .waitingConnectivity):
            logger.debug("Network is reachable. Resume monitoring.")

            startMonitoring()
            sendDelegateNetworkStatusChange(isReachable)

        case (false, .connecting), (false, .connected):
            logger.debug("Network is unreachable. Pause monitoring.")

            state = .waitingConnectivity
            stopMonitoring()
            sendDelegateNetworkStatusChange(isReachable)

        default:
            break
        }
    }

    private func startMonitoring() {
        do {
            guard let interfaceName = adapter.interfaceName else {
                logger.debug("Failed to obtain utun interface name.")
                return
            }

            try pinger.openSocket(bindTo: interfaceName)
        } catch {
            logger.error(chainedError: AnyChainedError(error), message: "Failed to open socket.")
            return
        }

        state = .connecting(
            startDate: Date(),
            transmitDate: nil,
            stats: WgStats()
        )

        startConnectivityCheckTimer()
    }

    private func stopMonitoring() {
        stopConnectivityCheckTimer()
        pinger.closeSocket()
        resetPingStats()
    }

    private func startConnectivityCheckTimer() {
        let timer = DispatchSource.makeTimerSource(queue: internalQueue)
        timer.setEventHandler { [weak self] in
            self?.checkConnectivity()
        }
        timer.schedule(wallDeadline: .now(), repeating: connectivityCheckInterval)
        timer.activate()

        self.timer?.cancel()
        self.timer = timer
    }

    private func stopConnectivityCheckTimer() {
        timer?.cancel()
        timer = nil
    }

    private func isPingTimedOut(now: Date, timeout: TimeInterval) -> Bool {
        guard let initialPingTimestamp = initialPingTimestamp else { return false }

        return now.timeIntervalSince(initialPingTimestamp) > timeout
    }

    private func maybeSendPing(now: Date) {
        guard let probeAddress = probeAddress else {
            return
        }

        guard lastPingTimestamp.map({ lastPingTimestamp in
            return now.timeIntervalSince(lastPingTimestamp) >= secondsPerPing
        }) ?? true else {
            return
        }

        if state.isReceiveTimedOut(now: now) {
            logger.debug("Receive timed out.")
        } else if state.isTrafficTimedOut(now: now) {
            logger.debug("Traffic timed out.")
        } else {
            return
        }

        logger.debug("Send ping.")

        do {
            _ = try pinger.send(to: probeAddress)

            if initialPingTimestamp == nil {
                initialPingTimestamp = now
            }

            lastPingTimestamp = now
        } catch {
            logger.error(chainedError: AnyChainedError(error), message: "Failed to send ping.")
        }
    }

    private func resetPingStats() {
        initialPingTimestamp = nil
        lastPingTimestamp = nil
    }

    private func sendDelegateConnectionEstablished() {
        delegateQueue.async {
            self.delegate?.tunnelMonitorDidDetermineConnectionEstablished(self)
        }
    }

    private func sendDelegateShouldHandleConnectionRecovery(completion: @escaping () -> Void) {
        delegateQueue.async {
            self.delegate?.tunnelMonitorDelegate(
                self,
                shouldHandleConnectionRecoveryWithCompletion: completion
            )
        }
    }

    private func sendDelegateNetworkStatusChange(_ isNetworkReachable: Bool) {
        delegateQueue.async {
            self.delegate?.tunnelMonitor(
                self,
                networkReachabilityStatusDidChange: isNetworkReachable
            )
        }
    }

    private func getStats() -> WgStats? {
        var result: String?

        let dispatchGroup = DispatchGroup()
        dispatchGroup.enter()
        adapter.getRuntimeConfiguration { string in
            result = string
            dispatchGroup.leave()
        }
        dispatchGroup.wait()

        guard let result = result else {
            logger.debug("Received nil string for stats.")
            return nil
        }

        guard let newStats = WgStats(from: result) else {
            logger.debug("Couldn't parse stats.")
            return nil
        }

        return newStats
    }

    private func isNetworkPathReachable(_ networkPath: Network.NWPath) -> Bool {
        guard let tunName = adapter.interfaceName else { return false }

        // Check if utun is up.
        let utunUp = networkPath.availableInterfaces.contains { interface in
            return interface.name == tunName
        }

        guard utunUp else {
            return false
        }

        // Return false if utun is the only available interface.
        if networkPath.availableInterfaces.count == 1 {
            return false
        }

        switch networkPath.status {
        case .requiresConnection, .satisfied:
            return true
        case .unsatisfied:
            return false
        @unknown default:
            return false
        }
    }
}

/// Tunnel monitor state.
private enum State {
    /// Initialized and doing nothing.
    case stopped

    /// Establishing connection.
    case connecting(
        startDate: Date,
        transmitDate: Date?,
        stats: WgStats
    )

    /// Connection is established.
    case connected(
        receiveDate: Date,
        transmitDate: Date,
        stats: WgStats
    )

    /// Waiting for network connectivity.
    case waitingConnectivity

    /// Returns `true` if inbound traffic counter incremented.
    mutating func update(now: Date, newStats: WgStats) -> Bool {
        switch self {
        case .initialized, .waitingConnectivity:
            return false

        case let .connecting(startDate, transmitDate, oldStats):
            if newStats.bytesReceived > oldStats.bytesReceived {
                self = .connected(
                    receiveDate: now,
                    transmitDate: transmitDate ?? startDate,
                    stats: newStats
                )
                return true
            } else if newStats.bytesSent > oldStats.bytesSent {
                self = .connecting(
                    startDate: startDate,
                    transmitDate: now,
                    stats: newStats
                )
            }
            return false

        case let .connected(receiveDate, transmitDate, oldStats):
            let receivedNewBytes = newStats.bytesReceived > oldStats.bytesReceived

            self = .connected(
                receiveDate: receivedNewBytes ? now : receiveDate,
                transmitDate: newStats.bytesSent > oldStats.bytesSent ? now : transmitDate,
                stats: newStats
            )

            return receivedNewBytes
        }
    }

    /// Returns `true` if last time data was received too long ago.
    func isReceiveTimedOut(now: Date) -> Bool {
        switch self {
        case let .connecting(startDate, _, _):
            return now.timeIntervalSince(startDate) >= receiveBytesTimeout

        case let .connected(receiveDate, transmitDate, _):
            return transmitDate > receiveDate &&
                now.timeIntervalSince(receiveDate) >= receiveBytesTimeout

        case .initialized, .waitingConnectivity:
            return false
        }
    }

    /// Returns `true` if no data has been sent or received in a while.
    func isTrafficTimedOut(now: Date) -> Bool {
        switch self {
        case .connecting:
            return isReceiveTimedOut(now: now)

        case let .connected(receiveDate, transmitDate, _):
            return now.timeIntervalSince(receiveDate) >= trafficTimeout ||
                now.timeIntervalSince(transmitDate) >= trafficTimeout

        case .initialized, .waitingConnectivity:
            return false
        }
    }

    var isConnecting: Bool {
        if case .connecting = self {
            return true
        }
        return false
    }

    var isConnected: Bool {
        if case .connected = self {
            return true
        }
        return false
    }
}
