import Foundation

/// Persists the appliance connection.
///
/// The address (e.g. `"homeradar.local:8000"` or a raw LAN IP:port) is not
/// secret -- it's stored in `UserDefaults`. The pairing token IS secret --
/// it's stored in the Keychain via `KeychainTokenStore`.
final class ConnectionStore {
    private let defaults: UserDefaults
    private let keychain: KeychainTokenStore
    private static let addressKey = "org.homeradar.app.applianceAddress"

    init(defaults: UserDefaults = .standard, keychain: KeychainTokenStore = KeychainTokenStore()) {
        self.defaults = defaults
        self.keychain = keychain
    }

    var address: String? {
        defaults.string(forKey: Self.addressKey)
    }

    var token: String? {
        keychain.load()
    }

    /// Whether a full connection (address + token) has been saved. `RootView`
    /// uses this to decide whether to show the Connect flow or the tabs.
    var hasCredentials: Bool {
        guard let address, !address.isEmpty else { return false }
        guard let token, !token.isEmpty else { return false }
        return true
    }

    func save(address: String, token: String) {
        defaults.set(address, forKey: Self.addressKey)
        keychain.save(token)
    }

    func clear() {
        defaults.removeObject(forKey: Self.addressKey)
        keychain.delete()
    }
}
