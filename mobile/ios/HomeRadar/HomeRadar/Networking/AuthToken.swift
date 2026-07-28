import Foundation
import Security

/// The one place the pairing-token header name lives. If HomeRadar's API
/// ever switches this app over to a different header (or `Authorization:
/// Bearer <token>`), this is the only line that needs to change -- every
/// request already funnels through `HomeRadarClient.attachAuth(_:)`, the
/// single choke point that reads this constant.
enum AuthToken {
    static let headerName = "X-HomeRadar-Token"
}

/// Minimal Keychain-backed storage for the opaque pairing token.
///
/// The token is a secret -- it grants full API access to the paired
/// appliance -- so it lives in the Keychain, not `UserDefaults`. This
/// wrapper is intentionally tiny: `SecItemAdd`/`SecItemCopyMatching`/
/// `SecItemUpdate`/`SecItemDelete` only, no third-party dependency.
struct KeychainTokenStore {
    private let service: String
    private let account = "pairingToken"

    init(service: String = "org.homeradar.app.pairingToken") {
        self.service = service
    }

    private var baseQuery: [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
        ]
    }

    /// Inserts or overwrites the stored token.
    func save(_ token: String) {
        let data = Data(token.utf8)
        let query = baseQuery
        if SecItemCopyMatching(query as CFDictionary, nil) == errSecSuccess {
            let update: [String: Any] = [kSecValueData as String: data]
            SecItemUpdate(query as CFDictionary, update as CFDictionary)
        } else {
            var addQuery = query
            addQuery[kSecValueData as String] = data
            // Available as soon as the device is unlocked once after boot;
            // this token has no need to be readable before first unlock,
            // and shouldn't sync to iCloud Keychain (device-specific pairing).
            addQuery[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            SecItemAdd(addQuery as CFDictionary, nil)
        }
    }

    /// Returns the stored token, or `nil` if none has been saved.
    func load() -> String? {
        var query = baseQuery
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let data = item as? Data else { return nil }
        return String(data: data, encoding: .utf8)
    }

    /// Removes the stored token, if any. Safe to call when nothing is stored.
    func delete() {
        SecItemDelete(baseQuery as CFDictionary)
    }
}
