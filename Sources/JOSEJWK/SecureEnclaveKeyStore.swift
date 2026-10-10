// The keychain, like the Secure Enclave, is reached through Apple frameworks only.
#if canImport(CryptoKit) && canImport(Security)
    import CryptoKit
    import Foundation
    import JOSECore
    import Security

    /// Why a Secure Enclave key could not be stored in or loaded from the keychain.
    public enum SecureEnclaveKeyStoreError: Error, Sendable, Equatable {
        /// A keychain operation failed. `status` is the `OSStatus` Security.framework returned;
        /// `SecCopyErrorMessageString` turns it into text. `-34018` (`errSecMissingEntitlement`) on
        /// macOS means the process has no keychain-access-groups or application-identifier
        /// entitlement, which the data protection keychain requires.
        case keychainFailure(operation: String, status: OSStatus)
        /// The stored item is not something this device's Secure Enclave can restore.
        case storedKeyUnusable(description: String)
    }

    extension SecureEnclaveKeyStoreError: CustomStringConvertible {
        public var description: String {
            switch self {
            case .keychainFailure(let operation, let status):
                var message = "status \(status)"
                if let text = SecCopyErrorMessageString(status, nil) {
                    message = "\(text) (\(status))"
                }
                return "keychain \(operation) failed: \(message)"
            case .storedKeyUnusable(let description):
                return "the stored Secure Enclave key could not be restored: \(description)"
            }
        }
    }

    /// The keychain calls ``SecureEnclaveKeyStore`` makes, so that the store's logic can be tested
    /// without a keychain. The production conformance forwards to Security.framework.
    protocol KeychainOperations: Sendable {
        func add(_ attributes: [CFString: Any]) -> OSStatus
        func update(_ query: [CFString: Any], with attributes: [CFString: Any]) -> OSStatus
        func copyData(_ query: [CFString: Any]) -> (status: OSStatus, data: Data?)
        func delete(_ query: [CFString: Any]) -> OSStatus
    }

    struct SystemKeychain: KeychainOperations {
        func add(_ attributes: [CFString: Any]) -> OSStatus {
            SecItemAdd(attributes as CFDictionary, nil)
        }

        func update(_ query: [CFString: Any], with attributes: [CFString: Any]) -> OSStatus {
            SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        }

        func copyData(_ query: [CFString: Any]) -> (status: OSStatus, data: Data?) {
            var query = query
            query[kSecReturnData] = true
            query[kSecMatchLimit] = kSecMatchLimitOne
            var result: CFTypeRef?
            let status = SecItemCopyMatching(query as CFDictionary, &result)
            return (status, result as? Data)
        }

        func delete(_ query: [CFString: Any]) -> OSStatus {
            SecItemDelete(query as CFDictionary)
        }
    }

    /// Keeps the data representation of a ``SecureEnclaveSigner`` in the keychain.
    ///
    /// The stored blob is an encrypted reference that only this device's Secure Enclave can use, so
    /// the keychain item protects availability rather than secrecy. Its accessibility still decides
    /// whether the key can be loaded while the device is locked, which is why it is a required
    /// parameter of ``save(_:as:accessibility:)``.
    ///
    /// Items are written update-then-add, never delete-then-add: a delete that succeeds followed by
    /// an add that fails would lose a key that may be the only copy.
    public struct SecureEnclaveKeyStore: Sendable {
        /// The `kSecAttrService` the store's items share.
        public let service: String
        /// The keychain access group, for sharing with an app's extensions. `nil` uses the app's
        /// default group.
        public let accessGroup: String?
        private let keychain: any KeychainOperations

        public init(service: String, accessGroup: String? = nil) {
            self.init(service: service, accessGroup: accessGroup, keychain: SystemKeychain())
        }

        init(service: String, accessGroup: String?, keychain: any KeychainOperations) {
            self.service = service
            self.accessGroup = accessGroup
            self.keychain = keychain
        }

        private func query(name: String) -> [CFString: Any] {
            var query: [CFString: Any] = [
                kSecClass: kSecClassGenericPassword,
                kSecAttrService: service,
                kSecAttrAccount: name,
                // The data protection keychain on every platform, so that behaviour (and the
                // absence of UI prompts) is the same on macOS as on iOS.
                kSecUseDataProtectionKeychain: true,
            ]
            if let accessGroup {
                query[kSecAttrAccessGroup] = accessGroup
            }
            return query
        }

        /// Stores `signer`'s data representation under `name`, replacing any item already there.
        public func save(
            _ signer: SecureEnclaveSigner,
            as name: String,
            accessibility: SecureEnclaveAccessibility
        ) throws(SecureEnclaveKeyStoreError) {
            let attributes: [CFString: Any] = [
                kSecValueData: signer.dataRepresentation,
                kSecAttrAccessible: accessibility.protection,
            ]
            let updateStatus = keychain.update(query(name: name), with: attributes)
            if updateStatus == errSecSuccess {
                return
            }
            guard updateStatus == errSecItemNotFound else {
                throw .keychainFailure(operation: "update", status: updateStatus)
            }
            var item = query(name: name)
            for (key, value) in attributes {
                item[key] = value
            }
            let addStatus = keychain.add(item)
            guard addStatus == errSecSuccess else {
                throw .keychainFailure(operation: "add", status: addStatus)
            }
        }

        /// Restores the signer stored under `name`, or returns `nil` if there is none.
        public func load(_ name: String, keyID: KeyID? = nil) throws(SecureEnclaveKeyStoreError) -> SecureEnclaveSigner?
        {
            let (status, data) = keychain.copyData(query(name: name))
            if status == errSecItemNotFound {
                return nil
            }
            guard status == errSecSuccess, let data else {
                throw .keychainFailure(operation: "load", status: status)
            }
            do {
                return try SecureEnclaveSigner(dataRepresentation: data, keyID: keyID)
            } catch {
                throw .storedKeyUnusable(description: error.description)
            }
        }

        /// Removes the item stored under `name`. Removing an item that does not exist is not an error.
        public func remove(_ name: String) throws(SecureEnclaveKeyStoreError) {
            let status = keychain.delete(query(name: name))
            guard status == errSecSuccess || status == errSecItemNotFound else {
                throw .keychainFailure(operation: "delete", status: status)
            }
        }
    }
#endif
