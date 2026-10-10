#if canImport(CryptoKit) && canImport(Security)
    import CryptoKit
    import Foundation
    import JOSECore
    import Security
    import Testing

    @testable import JOSEJWK

    /// An in-memory keychain that records every call, so that the order of operations can be checked.
    private final class RecordingKeychain: KeychainOperations, @unchecked Sendable {
        // `@unchecked` because tests drive it from one task at a time; the lock below is for
        // the Sendable checker, not for real contention.
        private let lock = NSLock()
        private var items: [String: Data] = [:]
        private(set) var calls: [String] = []
        var failAddWith: OSStatus?
        var failUpdateWith: OSStatus?

        private func account(_ query: [CFString: Any]) -> String {
            guard let account = query[kSecAttrAccount] as? String else {
                return ""
            }
            return account
        }

        func add(_ attributes: [CFString: Any]) -> OSStatus {
            lock.lock()
            defer { lock.unlock() }
            calls.append("add \(account(attributes))")
            if let failAddWith {
                return failAddWith
            }
            guard items[account(attributes)] == nil else {
                return errSecDuplicateItem
            }
            guard let data = attributes[kSecValueData] as? Data else {
                return errSecParam
            }
            items[account(attributes)] = data
            return errSecSuccess
        }

        func update(_ query: [CFString: Any], with attributes: [CFString: Any]) -> OSStatus {
            lock.lock()
            defer { lock.unlock() }
            calls.append("update \(account(query))")
            if let failUpdateWith {
                return failUpdateWith
            }
            guard items[account(query)] != nil else {
                return errSecItemNotFound
            }
            guard let data = attributes[kSecValueData] as? Data else {
                return errSecParam
            }
            items[account(query)] = data
            return errSecSuccess
        }

        func copyData(_ query: [CFString: Any]) -> (status: OSStatus, data: Data?) {
            lock.lock()
            defer { lock.unlock() }
            calls.append("copy \(account(query))")
            guard let data = items[account(query)] else {
                return (errSecItemNotFound, nil)
            }
            return (errSecSuccess, data)
        }

        func delete(_ query: [CFString: Any]) -> OSStatus {
            lock.lock()
            defer { lock.unlock() }
            calls.append("delete \(account(query))")
            guard items.removeValue(forKey: account(query)) != nil else {
                return errSecItemNotFound
            }
            return errSecSuccess
        }

        func stored(_ name: String) -> Data? {
            lock.lock()
            defer { lock.unlock() }
            return items[name]
        }
    }

    /// A software stand-in for a Secure Enclave key, so that what is stored can be restored without
    /// hardware. Its data representation is the raw P-256 key.
    private struct SoftwareKey: SecureEnclaveSigningKey {
        let key: P256.Signing.PrivateKey

        var x963PublicKey: Data {
            key.publicKey.x963Representation
        }

        var dataRepresentation: Data {
            key.rawRepresentation
        }

        func rawSignature(for message: Data) throws -> Data {
            try key.signature(for: message).rawRepresentation
        }
    }

    @Suite("SecureEnclaveKeyStore")
    struct SecureEnclaveKeyStoreTests {
        private func store(_ keychain: RecordingKeychain) -> SecureEnclaveKeyStore {
            SecureEnclaveKeyStore(service: "com.example.keys", accessGroup: nil, keychain: keychain)
        }

        @Test("a first save tries update, then adds; a second save updates in place")
        func updateThenAdd() throws {
            let keychain = RecordingKeychain()
            let store = store(keychain)
            let signer = try SecureEnclaveSigner(key: SoftwareKey(key: P256.Signing.PrivateKey()), keyID: nil)

            try store.save(signer, as: "device", accessibility: .afterFirstUnlockThisDeviceOnly)
            #expect(keychain.calls == ["update device", "add device"])
            #expect(keychain.stored("device") == signer.dataRepresentation)

            let replacement = try SecureEnclaveSigner(key: SoftwareKey(key: P256.Signing.PrivateKey()), keyID: nil)
            try store.save(replacement, as: "device", accessibility: .afterFirstUnlockThisDeviceOnly)
            #expect(keychain.calls == ["update device", "add device", "update device"])
            #expect(keychain.stored("device") == replacement.dataRepresentation)
            // At no point was anything deleted.
            #expect(!keychain.calls.contains { $0.hasPrefix("delete") })
        }

        @Test("a failed add leaves no item behind and reports the status; a failed update is reported as such")
        func failures() throws {
            let keychain = RecordingKeychain()
            let store = store(keychain)
            let signer = try SecureEnclaveSigner(key: SoftwareKey(key: P256.Signing.PrivateKey()), keyID: nil)

            keychain.failAddWith = errSecMissingEntitlement
            #expect(
                throws: SecureEnclaveKeyStoreError.keychainFailure(operation: "add", status: errSecMissingEntitlement)
            ) {
                try store.save(signer, as: "device", accessibility: .whenUnlockedThisDeviceOnly)
            }
            #expect(keychain.stored("device") == nil)

            keychain.failAddWith = nil
            keychain.failUpdateWith = errSecInteractionNotAllowed
            #expect(
                throws: SecureEnclaveKeyStoreError.keychainFailure(
                    operation: "update",
                    status: errSecInteractionNotAllowed
                )
            ) {
                try store.save(signer, as: "device", accessibility: .whenUnlockedThisDeviceOnly)
            }
            #expect(keychain.calls == ["update device", "add device", "update device"])
        }

        @Test("loading an absent item returns nil; removing one that is absent is not an error")
        func absentItems() throws {
            let keychain = RecordingKeychain()
            let store = store(keychain)
            #expect(try store.load("nothing") == nil)
            try store.remove("nothing")
            #expect(keychain.calls == ["copy nothing", "delete nothing"])
        }

        @Test("items carry the chosen accessibility, the service, and the access group")
        func attributes() throws {
            final class CapturingKeychain: KeychainOperations, @unchecked Sendable {
                var added: [CFString: Any] = [:]
                func add(_ attributes: [CFString: Any]) -> OSStatus {
                    added = attributes
                    return errSecSuccess
                }
                func update(_ query: [CFString: Any], with attributes: [CFString: Any]) -> OSStatus {
                    errSecItemNotFound
                }
                func copyData(_ query: [CFString: Any]) -> (status: OSStatus, data: Data?) {
                    (errSecItemNotFound, nil)
                }
                func delete(_ query: [CFString: Any]) -> OSStatus {
                    errSecSuccess
                }
            }
            let keychain = CapturingKeychain()
            let store = SecureEnclaveKeyStore(service: "svc", accessGroup: "TEAM.group", keychain: keychain)
            let signer = try SecureEnclaveSigner(key: SoftwareKey(key: P256.Signing.PrivateKey()), keyID: nil)
            try store.save(signer, as: "k", accessibility: .afterFirstUnlockThisDeviceOnly)
            #expect(keychain.added[kSecAttrService] as? String == "svc")
            #expect(keychain.added[kSecAttrAccount] as? String == "k")
            #expect(keychain.added[kSecAttrAccessGroup] as? String == "TEAM.group")
            #expect(keychain.added[kSecClass] as? String == kSecClassGenericPassword as String)
            #expect(keychain.added[kSecUseDataProtectionKeychain] as? Bool == true)
            #expect(
                keychain.added[kSecAttrAccessible] as? String == kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                    as String
            )
            #expect(keychain.added[kSecValueData] as? Data == signer.dataRepresentation)
        }

        @Test("a stored blob that the enclave cannot restore is reported, not returned")
        func unusableStoredItem() throws {
            guard SecureEnclave.isAvailable else {
                return
            }
            let keychain = RecordingKeychain()
            let store = store(keychain)
            // Write garbage directly, as a corrupted or foreign item would be.
            _ = keychain.add([kSecAttrAccount: "bad", kSecValueData: Data("not a key".utf8)])
            do {
                _ = try store.load("bad")
                Issue.record("garbage was restored as a key")
            } catch {
                guard case .storedKeyUnusable = error else {
                    Issue.record("unexpected error \(error)")
                    return
                }
            }
        }

        // Against the real keychain and the real Secure Enclave. The data protection keychain needs
        // an entitlement that a plain `swift test` process does not have, so on most machines this
        // reports that it could not run rather than passing vacuously.
        @Test("real keychain: save, load, sign and remove", .enabled(if: SecureEnclave.isAvailable))
        func realKeychain() async throws {
            let store = SecureEnclaveKeyStore(service: "dev.jose.tests.\(UUID().uuidString)")
            let signer: SecureEnclaveSigner
            do {
                signer = try SecureEnclaveSigner.generate(accessibility: .whenUnlockedThisDeviceOnly, keyID: "hw")
            } catch {
                print("note: Secure Enclave unusable from this process, real keychain test skipped: \(error)")
                return
            }
            do {
                try store.save(signer, as: "hw", accessibility: .whenUnlockedThisDeviceOnly)
            } catch {
                print("note: keychain not usable from this process, real keychain test skipped: \(error)")
                return
            }
            defer {
                do {
                    try store.remove("hw")
                } catch {
                    print("note: could not remove the test keychain item: \(error)")
                }
            }
            let loaded = try #require(try store.load("hw", keyID: "hw"))
            #expect(loaded.publicKey == signer.publicKey)
            let message = Data("stored".utf8)
            try ECDSAVerifier(publicKey: signer.publicKey).verify(try await loaded.sign(message), for: message)
            try store.remove("hw")
            #expect(try store.load("hw") == nil)
            print("note: real keychain test ran against the keychain and Secure Enclave")
        }

        @Test("errors have messages that include the status")
        func descriptions() {
            #expect(
                SecureEnclaveKeyStoreError.keychainFailure(operation: "add", status: -34018).description.contains(
                    "-34018"
                )
            )
            #expect(SecureEnclaveKeyStoreError.storedKeyUnusable(description: "why").description.contains("why"))
        }
    }
#endif
