//
//  MapConnectionStatusOperation.swift
//  MullvadVPN
//
//  Created by pronebird on 15/12/2021.
//  Copyright © 2021 Mullvad VPN AB. All rights reserved.
//

import Foundation
import Logging
import NetworkExtension

class MapConnectionStatusOperation: AsyncOperation {
    private let interactor: TunnelInteractor
    private let connectionStatus: NEVPNStatus
    private var request: Cancellable?

    private let logger = Logger(label: "TunnelManager.MapConnectionStatusOperation")

    init(
        queue: DispatchQueue,
        interactor: TunnelInteractor,
        connectionStatus: NEVPNStatus
    ) {
        self.interactor = interactor
        self.connectionStatus = connectionStatus

        super.init(dispatchQueue: queue)
    }

    override func main() {
        guard let tunnel = interactor.tunnel else {
            finish()
            return
        }

        let tunnelState = interactor.tunnelStatus.state

        switch connectionStatus {
        case .connecting:
            switch tunnelState {
            case .connecting:
                break

            default:
                var newTunnelStatus = interactor.tunnelStatus
                newTunnelStatus.state = .connecting(nil)
                interactor.setTunnelStatus(newTunnelStatus)
            }

            fetchTunnelStatus(tunnel: tunnel) { packetTunnelStatus in
                if packetTunnelStatus.isNetworkReachable {
                    return packetTunnelStatus.tunnelRelay.map { .connecting($0) }
                } else {
                    return .waitingForConnectivity
                }
            }
            return

        case .reasserting:
            fetchTunnelStatus(tunnel: tunnel) { packetTunnelStatus in
                if packetTunnelStatus.isNetworkReachable {
                    return packetTunnelStatus.tunnelRelay.map { .reconnecting($0) }
                } else {
                    return .waitingForConnectivity
                }
            }
            return

        case .connected:
            fetchTunnelStatus(tunnel: tunnel) { packetTunnelStatus in
                if packetTunnelStatus.isNetworkReachable {
                    return packetTunnelStatus.tunnelRelay.map { .connected($0) }
                } else {
                    return .waitingForConnectivity
                }
            }
            return

        case .disconnected:
            switch tunnelState {
            case .pendingReconnect:
                logger.debug("Ignore disconnected state when pending reconnect.")

            case .disconnecting(.reconnect):
                logger.debug("Restart the tunnel on disconnect.")

                var newTunnelStatus = TunnelStatus()
                newTunnelStatus.state = .pendingReconnect
                interactor.setTunnelStatus(newTunnelStatus)
                interactor.startTunnel()

            default:
                var newTunnelStatus = TunnelStatus()
                newTunnelStatus.state = .disconnected
                interactor.setTunnelStatus(newTunnelStatus)
            }

        case .disconnecting:
            switch tunnelState {
            case .disconnecting:
                break
            default:
                var newTunnelStatus = TunnelStatus()
                newTunnelStatus.state = .disconnecting(.nothing)
                interactor.setTunnelStatus(newTunnelStatus)
            }

        case .invalid:
            var newTunnelStatus = TunnelStatus()
            newTunnelStatus.state = .disconnected
            interactor.setTunnelStatus(newTunnelStatus)

        @unknown default:
            logger.debug("Unknown NEVPNStatus: \(connectionStatus.rawValue)")
        }

        finish()
    }

    override func operationDidCancel() {
        request?.cancel()
    }

    private func fetchTunnelStatus(
        tunnel: Tunnel,
        mapToState: @escaping (PacketTunnelStatus) -> TunnelState?
    ) {
        request = tunnel.getTunnelStatus { [weak self] completion in
            guard let self = self else { return }

            self.dispatchQueue.async {
                if case let .success(packetTunnelStatus) = completion, !self.isCancelled {
                    var newTunnelStatus = self.interactor.tunnelStatus
                    newTunnelStatus.packetTunnelStatus = packetTunnelStatus

                    if let newState = mapToState(packetTunnelStatus) {
                        newTunnelStatus.state = newState
                    }

                    self.interactor.setTunnelStatus(newTunnelStatus)
                }

                self.finish()
            }
        }
    }
}
