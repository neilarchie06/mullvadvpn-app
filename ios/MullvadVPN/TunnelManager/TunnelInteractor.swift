//
//  TunnelInteractor.swift
//  MullvadVPN
//
//  Created by pronebird on 05/07/2022.
//  Copyright © 2022 Mullvad VPN AB. All rights reserved.
//

import Foundation

protocol TunnelInteractor {
    // MARK: - Tunnel manipulation

    var tunnel: Tunnel? { get }
    func setTunnel(_ tunnel: Tunnel?, shouldRefreshTunnelState: Bool)

    // MARK: - Tunnel status

    var tunnelStatus: TunnelStatus { get }
    func setTunnelStatus(_ tunnelStatus: TunnelStatus)

    // MARK: - Configuration

    var isConfigurationLoaded: Bool { get }
    var settings: TunnelSettingsV2 { get }
    var deviceState: DeviceState { get }

    func setConfigurationLoaded()
    func setSettings(_ settings: TunnelSettingsV2, persist: Bool)
    func setDeviceState(_ deviceState: DeviceState, persist: Bool)

    func startTunnel()
    func prepareForVPNConfigurationDeletion()
}
