import Foundation
import Security

/// Keychain-backed `SecretStore`: items never leave this device and need an unlocked phone.
final class KeychainStore: SecretStore {
    private let service: String

    init(service: String = "tecdsa-bench") {
        self.service = service
    }

    private func query(_ key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
        ]
    }

    func put(key: String, value: Data) throws {
        var attrs = query(key)
        let update = [kSecValueData as String: value]
        var status = SecItemUpdate(attrs as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            attrs[kSecValueData as String] = value
            attrs[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            status = SecItemAdd(attrs as CFDictionary, nil)
        }
        guard status == errSecSuccess else { throw TecdsaError.Storage }
    }

    func get(key: String) throws -> Data? {
        var q = query(key)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = out as? Data else { throw TecdsaError.Storage }
        return data
    }

    func delete(key: String) throws {
        let status = SecItemDelete(query(key) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw TecdsaError.Storage }
    }
}
