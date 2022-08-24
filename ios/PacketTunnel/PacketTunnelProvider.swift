//
//  PacketTunnelProvider.swift
//  PacketTunnel
//
//  Created by pronebird on 19/03/2019.
//  Copyright © 2019 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Logging
import Network
import NetworkExtension
import WireGuardKit

class PacketTunnelProvider: NEPacketTunnelProvider, TunnelMonitorDelegate {
    /// Tunnel provider logger.
    private let providerLogger: Logger

    /// WireGuard adapter logger.
    private let tunnelLogger: Logger

    /// Internal queue.
    private let dispatchQueue = DispatchQueue(label: "PacketTunnel", qos: .utility)

    /// WireGuard adapter.
    private var adapter: WireGuardAdapter!

    /// Raised once tunnel establishes connection in the very first time, before calling the system
    /// completion handler passed into `startTunnel`.
    private var isConnected = false

    /// Flag indicating whether network is reachable.
    private var isNetworkReachable = true

    /// Current selector result.
    private var selectorResult: RelaySelectorResult?

    /// A system completion handler passed from startTunnel and saved for later use once the
    /// connection is established.
    private var startTunnelCompletionHandler: (() -> Void)?

    /// A completion handler passed during reassertion and saved for later use once the connection
    /// is reestablished.
    private var reassertTunnelCompletionHandler: (() -> Void)?

    /// Tunnel monitor.
    private var tunnelMonitor: TunnelMonitor!

    /// Returns `PacketTunnelStatus` used for sharing with main bundle process.
    private var packetTunnelStatus: PacketTunnelStatus {
        return PacketTunnelStatus(
            isNetworkReachable: isNetworkReachable,
            tunnelRelay: selectorResult?.packetTunnelRelay
        )
    }

    override init() {
        let pid = ProcessInfo.processInfo.processIdentifier

        var metadata = Logger.Metadata()
        metadata["pid"] = .string("\(pid)")

        initLoggingSystem(bundleIdentifier: Bundle.main.bundleIdentifier!, metadata: metadata)

        providerLogger = Logger(label: "PacketTunnelProvider")
        tunnelLogger = Logger(label: "WireGuard")

        super.init()

        adapter = WireGuardAdapter(
            with: self,
            shouldHandleReasserting: false,
            logHandler: { [weak self] logLevel, message in
                self?.dispatchQueue.async {
                    self?.tunnelLogger.log(level: logLevel.loggerLevel, "\(message)")
                }
            }
        )

        tunnelMonitor = TunnelMonitor(queue: dispatchQueue, adapter: adapter)
        tunnelMonitor.delegate = self
    }

    override func startTunnel(
        options: [String: NSObject]?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        let tunnelOptions = PacketTunnelOptions(rawOptions: options ?? [:])
        var appSelectorResult: RelaySelectorResult?

        // Parse relay selector from tunnel options.
        do {
            appSelectorResult = try tunnelOptions.getSelectorResult()

            switch appSelectorResult {
            case let .some(selectorResult):
                providerLogger.debug(
                    "Start the tunnel via app, connect to \(selectorResult.relay.hostname)."
                )

            case .none:
                if tunnelOptions.isOnDemand() {
                    providerLogger.debug("Start the tunnel via on-demand rule.")
                } else {
                    providerLogger.debug("Start the tunnel via system.")
                }
            }
        } catch {
            providerLogger.debug("Start the tunnel via app.")
            providerLogger.error(
                chainedError: AnyChainedError(error),
                message: """
                Failed to decode relay selector result passed from the app. \
                Will continue by picking new relay.
                """
            )
        }

        // Read tunnel configuration.
        let tunnelConfiguration: PacketTunnelConfiguration
        do {
            tunnelConfiguration = try makeConfiguration(appSelectorResult)
        } catch {
            providerLogger.error(
                chainedError: AnyChainedError(error),
                message: "Failed to start the tunnel."
            )

            completionHandler(error)
            return
        }

        // Set tunnel status.
        dispatchQueue.async {
            let selectorResult = tunnelConfiguration.selectorResult
            self.selectorResult = selectorResult
            self.providerLogger.debug("Set tunnel relay to \(selectorResult.relay.hostname).")
        }

        // Start tunnel.
        adapter.start(tunnelConfiguration: tunnelConfiguration.wgTunnelConfig) { error in
            self.dispatchQueue.async {
                if let error = error {
                    self.providerLogger.error(
                        chainedError: AnyChainedError(error),
                        message: "Failed to start the tunnel."
                    )

                    completionHandler(error)
                } else {
                    self.providerLogger.debug("Started the tunnel.")

                    // Store completion handler and call it from TunnelMonitorDelegate once
                    // the connection is established.
                    self.startTunnelCompletionHandler = { [weak self] in
                        // Mark the tunnel connected.
                        self?.isConnected = true

                        // Call system completion handler.
                        completionHandler(nil)
                    }

                    // Start tunnel monitor.
                    let gatewayAddress = tunnelConfiguration.selectorResult.endpoint.ipv4Gateway

                    self.tunnelMonitor.start(address: gatewayAddress)
                }
            }
        }
    }

    override func stopTunnel(
        with reason: NEProviderStopReason,
        completionHandler: @escaping () -> Void
    ) {
        providerLogger.debug("Stop the tunnel: \(reason)")

        dispatchQueue.async {
            self.tunnelMonitor.stop()

            self.startTunnelCompletionHandler = nil
            self.reassertTunnelCompletionHandler = nil
        }

        adapter.stop { error in
            self.dispatchQueue.async {
                if let error = error {
                    self.providerLogger.error(
                        chainedError: AnyChainedError(error),
                        message: "Failed to stop the tunnel gracefully."
                    )
                } else {
                    self.providerLogger.debug("Stopped the tunnel.")
                }
                completionHandler()
            }
        }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        dispatchQueue.async {
            let message: TunnelProviderMessage
            do {
                message = try TunnelProviderMessage(messageData: messageData)
            } catch {
                self.providerLogger.error(
                    chainedError: AnyChainedError(error),
                    message: "Failed to decode the app message."
                )

                completionHandler?(nil)
                return
            }

            self.providerLogger.debug("Received app message: \(message)")

            switch message {
            case let .reconnectTunnel(appSelectorResult):
                self.providerLogger.debug("Reconnecting the tunnel...")

                self.reconnectTunnel(selectorResult: appSelectorResult) { [weak self] error in
                    guard let self = self else { return }

                    if let error = error {
                        self.providerLogger.error(
                            chainedError: AnyChainedError(error),
                            message: "Failed to reconnect the tunnel."
                        )
                    } else {
                        self.providerLogger.debug("Reconnected the tunnel.")
                    }
                }

                completionHandler?(nil)

            case .getTunnelStatus:
                var response: Data?
                do {
                    response = try TunnelProviderReply(self.packetTunnelStatus).encode()
                } catch {
                    self.providerLogger.error(
                        chainedError: AnyChainedError(error),
                        message: "Failed to encode tunnel status reply."
                    )
                }

                completionHandler?(response)
            }
        }
    }

    override func sleep(completionHandler: @escaping () -> Void) {
        // Add code here to get ready to sleep.
        completionHandler()
    }

    override func wake() {
        // Add code here to wake up.
    }

    // MARK: - TunnelMonitor

    func tunnelMonitorDidDetermineConnectionEstablished(_ tunnelMonitor: TunnelMonitor) {
        dispatchPrecondition(condition: .onQueue(dispatchQueue))

        providerLogger.debug("Connection established.")

        startTunnelCompletionHandler?()
        startTunnelCompletionHandler = nil

        reassertTunnelCompletionHandler?()
        reassertTunnelCompletionHandler = nil
    }

    func tunnelMonitorDelegate(
        _ tunnelMonitor: TunnelMonitor,
        shouldHandleConnectionRecoveryWithCompletion completionHandler: @escaping () -> Void
    ) {
        dispatchPrecondition(condition: .onQueue(dispatchQueue))

        providerLogger.debug("Recover connection. Picking next relay...")

        reconnectTunnel(selectorResult: nil) { error in
            completionHandler()
        }
    }

    func tunnelMonitor(
        _ tunnelMonitor: TunnelMonitor,
        networkReachabilityStatusDidChange isNetworkReachable: Bool
    ) {
        self.isNetworkReachable = isNetworkReachable
    }

    // MARK: - Private

    private func makeConfiguration(_ appSelectorResult: RelaySelectorResult? = nil)
        throws -> PacketTunnelConfiguration
    {
        let deviceState = try SettingsManager.readDeviceState()
        let tunnelSettings = try SettingsManager.readSettings()
        let selectorResult = try appSelectorResult
            ?? Self.selectRelayEndpoint(
                relayConstraints: tunnelSettings.relayConstraints
            )

        return PacketTunnelConfiguration(
            deviceState: deviceState,
            tunnelSettings: tunnelSettings,
            selectorResult: selectorResult
        )
    }

    private func reconnectTunnel(
        selectorResult aSelectorResult: RelaySelectorResult?,
        completionHandler: @escaping (Error?) -> Void
    ) {
        dispatchPrecondition(condition: .onQueue(dispatchQueue))

        // Read tunnel configuration.
        let tunnelConfiguration: PacketTunnelConfiguration
        do {
            tunnelConfiguration = try makeConfiguration(aSelectorResult ?? selectorResult)
        } catch {
            completionHandler(error)
            return
        }

        // Copy old relay.
        let oldSelectorResult = selectorResult
        let newTunnelRelay = tunnelConfiguration.selectorResult.packetTunnelRelay

        // Update tunnel status.
        selectorResult = tunnelConfiguration.selectorResult

        providerLogger.debug("Set tunnel relay to \(newTunnelRelay.hostname).")

        // Raise reasserting flag, but only if tunnel has already moved to connected state once.
        // Otherwise keep the app in connecting state until it manages to establish the very first
        // connection.
        if isConnected {
            reasserting = true
        }

        // Update WireGuard configuration.
        adapter.update(tunnelConfiguration: tunnelConfiguration.wgTunnelConfig) { error in
            self.dispatchQueue.async {
                // Reset previously stored completion handler.
                self.reassertTunnelCompletionHandler = nil

                // Call completion handler immediately on error to update adapter configuration.
                if let error = error {
                    // Revert to previously used relay selector.
                    self.selectorResult = oldSelectorResult
                    self.providerLogger.debug(
                        "Reset tunnel relay to \(oldSelectorResult?.relay.hostname ?? "none")."
                    )

                    // Lower the reasserting flag.
                    if self.isConnected {
                        self.reasserting = false
                    }

                    // Call completion handler immediately.
                    completionHandler(error)
                } else {
                    // Store completion handler and call it from TunnelMonitorDelegate once
                    // the connection is established.
                    self.reassertTunnelCompletionHandler = { [weak self] providerError in
                        guard let self = self else { return }

                        // Lower the reasserting flag.
                        if self.isConnected {
                            self.reasserting = false
                        }

                        completionHandler(providerError)
                    }

                    // Restart tunnel monitor.
                    let gatewayAddress = tunnelConfiguration.selectorResult.endpoint.ipv4Gateway

                    self.tunnelMonitor.start(address: gatewayAddress)
                }
            }
        }
    }

    /// Load relay cache with potential networking to refresh the cache and pick the relay for the
    /// given relay constraints.
    private class func selectRelayEndpoint(relayConstraints: RelayConstraints) throws
        -> RelaySelectorResult
    {
        let cacheFileURL = RelayCache.IO.defaultCacheFileURL(
            forSecurityApplicationGroupIdentifier: ApplicationConfiguration.securityGroupIdentifier
        )!
        let prebundledRelaysURL = RelayCache.IO.preBundledRelaysFileURL!
        let cachedRelayList = try RelayCache.IO.readWithFallback(
            cacheFileURL: cacheFileURL,
            preBundledRelaysFileURL: prebundledRelaysURL
        )

        return try RelaySelector.evaluate(
            relays: cachedRelayList.relays,
            constraints: relayConstraints
        )
    }
}
