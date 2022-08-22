//
//  OutOfTimeViewController.swift
//  MullvadVPN
//
//  Created by Andreas Lif on 2022-07-25.
//  Copyright © 2022 Mullvad VPN AB. All rights reserved.
//

import Foundation
import StoreKit
import UIKit

class OutOfTimeViewController: UIViewController {
    weak var delegate: SettingsButtonInteractionDelegate?

    private var productState: ProductState = .none
    private var paymentState: PaymentState = .none

    private let alertPresenter = AlertPresenter()

    private let scrollView: UIScrollView = {
        let scrollView = UIScrollView()
        scrollView.translatesAutoresizingMaskIntoConstraints = false
        scrollView.indicatorStyle = .white
        return scrollView
    }()
    
    private let contentView: OutOfTimeContentView = {
        let contentView = OutOfTimeContentView()
        contentView.translatesAutoresizingMaskIntoConstraints = false
        return contentView
    }()

    override var preferredStatusBarStyle: UIStatusBarStyle {
        return .lightContent
    }

    private var tunnelState: TunnelState = .disconnected

    private func setTunnelState(_ newState: TunnelState, animated: Bool) {
        setNeedsHeaderBarStyleAppearanceUpdate()
        applyViewState(animated: animated)
    }

    override func viewDidLoad() {
        super.viewDidLoad()

        view.backgroundColor = .secondaryColor

        setUpSubviews()
        setUpButtonTargets()
        setUpInAppPurchases()
        addObservers()
        setTunnelState(TunnelManager.shared.tunnelStatus.state, animated: false)
    }
}

// MARK: - Private Functions

private extension OutOfTimeViewController {
    
    func setUpSubviews() {
        scrollView.addSubview(contentView)
        view.addSubview(scrollView)
        
        configureConstraints()
    }
    
    func configureConstraints() {
        NSLayoutConstraint.activate([
            scrollView.topAnchor.constraint(equalTo: view.safeAreaLayoutGuide.topAnchor),
            scrollView.leadingAnchor.constraint(equalTo: view.leadingAnchor),
            scrollView.trailingAnchor.constraint(equalTo: view.trailingAnchor),
            scrollView.bottomAnchor.constraint(equalTo: view.bottomAnchor),

            contentView.topAnchor.constraint(equalTo: scrollView.topAnchor),
            contentView.bottomAnchor.constraint(equalTo: scrollView.bottomAnchor),
            contentView.leadingAnchor.constraint(equalTo: scrollView.leadingAnchor),
            contentView.trailingAnchor.constraint(equalTo: scrollView.trailingAnchor),
            contentView.widthAnchor.constraint(equalTo: scrollView.widthAnchor),

            contentView.heightAnchor.constraint(
                greaterThanOrEqualTo: scrollView.frameLayoutGuide.heightAnchor
            ),
        ])
    }

    func setUpButtonTargets() {
        contentView.disconnectButton.addTarget(
            self,
            action: #selector(handleDisconnect(_:)),
            for: .touchUpInside
        )

        contentView.purchaseButton.addTarget(
            self,
            action: #selector(doPurchase),
            for: .touchUpInside
        )
        contentView.restoreButton.addTarget(
            self,
            action: #selector(restorePurchases),
            for: .touchUpInside
        )
        contentView.redeemButton.addTarget(
            self,
            action: #selector(didTapRedeemVoucher),
            for: .touchUpInside
        )
    }

    @objc func handleDisconnect(_ sender: Any) {
        TunnelManager.shared.stopTunnel()
    }
    
    @objc func didTapRedeemVoucher() {
        rootContainerController?.pushViewController(RedeemVoucherViewController(), animated: true)
    }

    func addObservers() {
        AppStorePaymentManager.shared.addPaymentObserver(self)
        TunnelManager.shared.addObserver(self)
    }

    func bodyText(for tunnelState: TunnelState) -> String {
        if tunnelState.isSecured {
            return NSLocalizedString(
                "OUT_OF_TIME_BODY_CONNECTED",
                tableName: "OutOfTime",
                value: "You have no more VPN time left on this account. To add more, you will need to disconnect and access the Internet with an unsecure connection.",
                comment: ""
            )
        } else {
            return NSLocalizedString(
                "OUT_OF_TIME_BODY_DISCONNECTED",
                tableName: "OutOfTime",
                value: "You have no more VPN time left on this account. Either buy credit on our website or redeem a voucher.",
                comment: ""
            )
        }
    }
}

// MARK: - In App Purchases

private extension OutOfTimeViewController {
    func setUpInAppPurchases() {
        if AppStorePaymentManager.canMakePayments {
            requestStoreProducts()
        } else {
            setProductState(.cannotMakePurchases, animated: false)
        }
    }

    func requestStoreProducts() {
        let productKind = AppStoreSubscription.thirtyDays

        setProductState(.fetching(productKind), animated: true)

        _ = AppStorePaymentManager.shared
            .requestProducts(with: [productKind]) { [weak self] completion in
                let productState: ProductState = completion.value?.products.first
                    .map { .received($0) } ?? .failed

                self?.setProductState(productState, animated: true)
            }
    }

    func setPaymentState(_ newState: PaymentState, animated: Bool) {
        paymentState = newState

        applyViewState(animated: animated)
    }

    func setProductState(_ newState: ProductState, animated: Bool) {
        productState = newState

        applyViewState(animated: false)
    }

    func applyViewState(animated: Bool) {
        let isInteractionEnabled = paymentState.allowsViewInteraction
        let purchaseButton = contentView.purchaseButton

        let isOutOfTime = TunnelManager.shared.deviceState.accountData
            .map { $0.expiry < Date() } ?? false

        let actions = { [weak self] in
            guard let self = self else { return }

            purchaseButton.setTitle(self.productState.purchaseButtonTitle, for: .normal)
            self.contentView.purchaseButton.isLoading = self.productState.isFetching

            purchaseButton.isEnabled = self.productState.isReceived && isInteractionEnabled && !self
                .tunnelState.isSecured
            self.contentView.redeemButton.isEnabled = isInteractionEnabled && !self
                .tunnelState.isSecured
            self.contentView.restoreButton.isEnabled = isInteractionEnabled && !self.tunnelState.isSecured
            self.contentView.disconnectButton.isEnabled = self.tunnelState.isSecured
            self.contentView.disconnectButton.alpha = self.tunnelState.isSecured ? 1 : 0
            self.contentView.bodyLabel.text = self.bodyText(for: self.tunnelState)

            if !isInteractionEnabled {
                self.contentView.statusActivityView.state = .activity
            } else {
                self.contentView.statusActivityView.state = isOutOfTime ? .failure : .success
            }

            self.delegate?.viewController(
                self,
                didRequestSettingsButtonEnabled: isInteractionEnabled
            )
        }
        if animated {
            UIView.animate(withDuration: 0.25, animations: {
                actions()
                self.view.layoutIfNeeded()
            }
                )
        } else {
            actions()
        }

        view.isUserInteractionEnabled = isInteractionEnabled
        if #available(iOS 13.0, *) {
            isModalInPresentation = !isInteractionEnabled
        }
        navigationItem.setHidesBackButton(!isInteractionEnabled, animated: animated)
    }

    @objc private func doPurchase() {
        guard case let .received(product) = productState,
              let accountData = TunnelManager.shared.deviceState.accountData
        else {
            return
        }

        let payment = SKPayment(product: product)
        AppStorePaymentManager.shared.addPayment(payment, for: accountData.number)

        setPaymentState(.makingPayment(payment), animated: true)
    }

    @objc func restorePurchases() {
        guard let accountData = TunnelManager.shared.deviceState.accountData else {
            return
        }

        setPaymentState(.restoringPurchases, animated: true)

        _ = AppStorePaymentManager.shared.restorePurchases(for: accountData.number) { completion in
            switch completion {
            case let .success(response):
                self.showAlertIfNoTimeAdded(with: response, context: .restoration)
            case let .failure(error):
                self.showRestorePurchasesErrorAlert(error: error)

            case .cancelled:
                break
            }

            self.setPaymentState(.none, animated: true)
        }
    }

    private func showAlertIfNoTimeAdded(
        with response: REST.CreateApplePaymentResponse,
        context: REST.CreateApplePaymentResponse.Context
    ) {
        guard case .noTimeAdded = response else { return }

        let alertController = UIAlertController(
            title: response.alertTitle(context: context),
            message: response.alertMessage(context: context),
            preferredStyle: .alert
        )
        alertController.addAction(
            UIAlertAction(
                title: NSLocalizedString(
                    "TIME_ADDED_ALERT_OK_ACTION",
                    tableName: "OutOfTime",
                    value: "OK",
                    comment: ""
                ),
                style: .cancel
            )
        )

        alertPresenter.enqueue(alertController, presentingController: self)
    }

    func showRestorePurchasesErrorAlert(error: AppStorePaymentManager.Error) {
        let alertController = UIAlertController(
            title: NSLocalizedString(
                "RESTORE_PURCHASES_FAILURE_ALERT_TITLE",
                tableName: "OutOfTime",
                value: "Cannot restore purchases",
                comment: ""
            ),
            message: error.errorChainDescription,
            preferredStyle: .alert
        )
        alertController.addAction(
            UIAlertAction(title: NSLocalizedString(
                "RESTORE_PURCHASES_FAILURE_ALERT_OK_ACTION",
                tableName: "OutOfTime",
                value: "OK",
                comment: ""
            ), style: .cancel)
        )
        alertPresenter.enqueue(alertController, presentingController: self)
    }

    func showPaymentErrorAlert(error: AppStorePaymentManager.Error) {
        let alertController = UIAlertController(
            title: NSLocalizedString(
                "CANNOT_COMPLETE_PURCHASE_ALERT_TITLE",
                tableName: "OutOfTime",
                value: "Cannot complete the purchase",
                comment: ""
            ),
            message: error.errorChainDescription,
            preferredStyle: .alert
        )

        alertController.addAction(
            UIAlertAction(
                title: NSLocalizedString(
                    "CANNOT_COMPLETE_PURCHASE_ALERT_OK_ACTION",
                    tableName: "OutOfTime",
                    value: "OK",
                    comment: ""
                ), style: .cancel
            )
        )

        alertPresenter.enqueue(alertController, presentingController: self)
    }

    func didProcessPayment(_ payment: SKPayment) {
        guard case let .makingPayment(pendingPayment) = paymentState,
              pendingPayment == payment else { return }

        setPaymentState(.none, animated: true)
    }
}

// MARK: - AppStorePaymentObserver

extension OutOfTimeViewController: AppStorePaymentObserver {
    func appStorePaymentManager(
        _ manager: AppStorePaymentManager,
        transaction: SKPaymentTransaction?,
        payment: SKPayment,
        accountToken: String?,
        didFailWithError error: AppStorePaymentManager.Error
    ) {
        switch error {
        case .storePayment(SKError.paymentCancelled):
            break

        default:
            showPaymentErrorAlert(error: error)
        }

        didProcessPayment(payment)
    }

    func appStorePaymentManager(
        _ manager: AppStorePaymentManager,
        transaction: SKPaymentTransaction,
        accountToken: String,
        didFinishWithResponse response: REST.CreateApplePaymentResponse
    ) {
        didProcessPayment(transaction.payment)
    }
}

// MARK: - TunnelObserver

extension OutOfTimeViewController: TunnelObserver {
    func tunnelManagerDidLoadConfiguration(_ manager: TunnelManager) {}

    func tunnelManager(_ manager: TunnelManager, didUpdateTunnelState tunnelState: TunnelState) {
        setTunnelState(tunnelState, animated: true)
    }

    func tunnelManager(_ manager: TunnelManager, didUpdateDeviceState deviceState: DeviceState) {}

    func tunnelManager(
        _ manager: TunnelManager,
        didUpdateTunnelSettings tunnelSettings: TunnelSettingsV2
    ) {}

    func tunnelManager(_ manager: TunnelManager, didFailWithError error: Error) {}
}

// MARK: - Header Bar

extension OutOfTimeViewController: RootContainment {
    var preferredHeaderBarPresentation: HeaderBarPresentation {
        return HeaderBarPresentation(
            style: tunnelState.isSecured ? .secured : .unsecured,
            showsDivider: false
        )
    }

    var prefersHeaderBarHidden: Bool {
        false
    }
}

// MARK: - UI Restrictions

private extension OutOfTimeViewController {
    enum PaymentState: Equatable {
        case none
        case makingPayment(SKPayment)
        case restoringPurchases

        var allowsViewInteraction: Bool {
            switch self {
            case .none:
                return true
            case .restoringPurchases, .makingPayment:
                return false
            }
        }
    }

    enum ProductState {
        case none
        case fetching(AppStoreSubscription)
        case received(SKProduct)
        case failed
        case cannotMakePurchases

        var isFetching: Bool {
            if case .fetching = self {
                return true
            }
            return false
        }

        var isReceived: Bool {
            if case .received = self {
                return true
            }
            return false
        }

        var purchaseButtonTitle: String? {
            switch self {
            case .none:
                return nil

            case let .fetching(subscription):
                return subscription.localizedTitle

            case let .received(product):
                let localizedTitle = product.customLocalizedTitle ?? ""
                let localizedPrice = product.localizedPrice ?? ""

                let format = NSLocalizedString(
                    "PURCHASE_BUTTON_TITLE_FORMAT",
                    tableName: "OutOfTime",
                    value: "%1$@ (%2$@)",
                    comment: ""
                )
                return String(format: format, localizedTitle, localizedPrice)

            case .failed:
                return NSLocalizedString(
                    "PURCHASE_BUTTON_CANNOT_CONNECT_TO_APPSTORE_LABEL",
                    tableName: "OutOfTime",
                    value: "Cannot connect to AppStore",
                    comment: ""
                )

            case .cannotMakePurchases:
                return NSLocalizedString(
                    "PURCHASE_BUTTON_PAYMENTS_RESTRICTED_LABEL",
                    tableName: "OutOfTime",
                    value: "Payments restricted",
                    comment: ""
                )
            }
        }
    }
}
