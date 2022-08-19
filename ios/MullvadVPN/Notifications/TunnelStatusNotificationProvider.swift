//
//  TunnelStatusNotificationProvider.swift
//  TunnelStatusNotificationProvider
//
//  Created by pronebird on 20/08/2021.
//  Copyright © 2021 Mullvad VPN AB. All rights reserved.
//

import Foundation

class TunnelStatusNotificationProvider: NotificationProvider, InAppNotificationProvider,
    TunnelObserver
{
    private enum State {
        case `default`
        case waitingForConnectivity
        case failure(Error)

        var isDefault: Bool {
            if case .default = self {
                return true
            }
            return false
        }

        var isWaitingForConnectivity: Bool {
            if case .waitingForConnectivity = self {
                return true
            }
            return false
        }
    }

    private var state: State = .default {
        didSet {
            invalidate()
        }
    }

    override var identifier: String {
        return "net.mullvad.MullvadVPN.TunnelStatusNotificationProvider"
    }

    var notificationDescriptor: InAppNotificationDescriptor? {
        switch state {
        case .default:
            return nil

        case .waitingForConnectivity:
            return InAppNotificationDescriptor(
                identifier: identifier,
                style: .warning,
                title: NSLocalizedString(
                    "TUNNEL_NO_CONNECTIVITY_INAPP_NOTIFICATION_TITLE",
                    value: "BLOCKING INTERNET",
                    comment: ""
                ),
                body: NSLocalizedString(
                    "TUNNEL_NO_CONNECTIVITY_INAPP_NOTIFICATION_BODY",
                    value: "Your device is offline. The tunnel will automatically connect once your device is back online.",
                    comment: ""
                )
            )

        case let .failure(error):
            let body = (error as? LocalizedNotificationError)?.localizedNotificationBody ?? error
                .localizedDescription

            return InAppNotificationDescriptor(
                identifier: identifier,
                style: .error,
                title: NSLocalizedString(
                    "TUNNEL_ERROR_INAPP_NOTIFICATION_TITLE",
                    value: "TUNNEL ERROR",
                    comment: ""
                ),
                body: body
            )
        }
    }

    override init() {
        super.init()

        let tunnelManager = TunnelManager.shared

        tunnelManager.addObserver(self)
        handleTunnelState(tunnelManager.tunnelStatus.state)
    }

    private func handleTunnelState(_ tunnelState: TunnelState) {
        switch tunnelState {
        case .connecting, .connected, .reconnecting:
            // Remove all messages, connectivity will be updated upon the tunnel startup.
            if !state.isDefault {
                state = .default
            }

        case .waitingForConnectivity:
            if !state.isWaitingForConnectivity {
                state = .waitingForConnectivity
            }

        case .disconnecting, .disconnected:
            // Leave failure on screen once disconnected but remove connectivity message.
            if state.isWaitingForConnectivity {
                state = .default
            }

        default:
            break
        }
    }

    // MARK: - TunnelObserver

    func tunnelManagerDidLoadConfiguration(_ manager: TunnelManager) {
        // no-op
    }

    func tunnelManager(_ manager: TunnelManager, didUpdateTunnelState tunnelState: TunnelState) {
        handleTunnelState(tunnelState)
    }

    func tunnelManager(
        _ manager: TunnelManager,
        didUpdateTunnelSettings tunnelSettings: TunnelSettingsV2
    ) {
        // no-op
    }

    func tunnelManager(_ manager: TunnelManager, didUpdateDeviceState deviceState: DeviceState) {
        // no-op
    }

    func tunnelManager(_ manager: TunnelManager, didFailWithError error: Error) {
        state = .failure(error)
    }
}

protocol LocalizedNotificationError {
    var localizedNotificationBody: String? { get }
}

extension StartTunnelError: LocalizedNotificationError {
    var localizedNotificationBody: String? {
        return String(
            format: NSLocalizedString(
                "START_TUNNEL_ERROR_INAPP_NOTIFICATION_BODY",
                value: "Failed to start the tunnel: %@.",
                comment: ""
            ),
            underlyingError.localizedDescription
        )
    }
}

extension StopTunnelError: LocalizedNotificationError {
    var localizedNotificationBody: String? {
        return String(
            format: NSLocalizedString(
                "STOP_TUNNEL_ERROR_INAPP_NOTIFICATION_BODY",
                value: "Failed to stop the tunnel: %@.",
                comment: ""
            ),
            underlyingError.localizedDescription
        )
    }
}
