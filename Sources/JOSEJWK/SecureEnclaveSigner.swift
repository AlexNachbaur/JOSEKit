// The Secure Enclave is reached through CryptoKit, which exists only on Apple platforms.
// swift-crypto has no equivalent, so nothing in this file is compiled elsewhere.
#if canImport(CryptoKit)
    import CryptoKit
    import Foundation
    import JOSECore
    import Security

    /// What ``SecureEnclaveSigner`` needs from a key. This is the seam for testing: the real
    /// conformance wraps a Secure Enclave key, and tests supply their own, so that everything in the
    /// signer — public key validation, error mapping, signature checking — runs the same code either
    /// way.
    protocol SecureEnclaveSigningKey: Sendable {
        /// The public key as an uncompressed X9.63 point.
        var x963PublicKey: Data { get }
        /// An opaque blob from which the key can be restored on the same device.
        var dataRepresentation: Data { get }
        /// Signs `message` (hashing it with SHA-256) and returns `r || s`.
        func rawSignature(for message: Data) throws -> Data
    }

    extension SecureEnclave.P256.Signing.PrivateKey: SecureEnclaveSigningKey {
        var x963PublicKey: Data {
            publicKey.x963Representation
        }

        func rawSignature(for message: Data) throws -> Data {
            try signature(for: message).rawRepresentation
        }
    }

    #if DEBUG && targetEnvironment(simulator)
        /// The simulator has no Secure Enclave. This stands in for one so that code using
        /// ``SecureEnclaveSigner`` can run there. It is an ordinary in-memory key with none of the
        /// Secure Enclave's protection, and the condition above keeps it out of every release build and
        /// every device build.
        struct SimulatorSoftwareKey: SecureEnclaveSigningKey {
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
    #endif

    /// When a Secure Enclave key may be used. There is no default: the choice decides whether
    /// signing works in the background, so it has to be made deliberately.
    public enum SecureEnclaveAccessibility: Sendable {
        /// Usable only while the device is unlocked. Signing from the background on a locked device
        /// fails with `errSecInteractionNotAllowed`.
        case whenUnlockedThisDeviceOnly
        /// Usable any time after the first unlock following a restart. Choose this if the key signs
        /// in background tasks, push handlers or anything else that can run while the device is locked.
        case afterFirstUnlockThisDeviceOnly

        var protection: CFString {
            switch self {
            case .whenUnlockedThisDeviceOnly:
                return kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            case .afterFirstUnlockThisDeviceOnly:
                return kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
            }
        }
    }

    /// Why a Secure Enclave key could not be created or restored.
    public enum SecureEnclaveError: Error, Sendable {
        /// This device (or the simulator, in a release build) has no Secure Enclave.
        case unavailable
        case accessControlCreationFailed(description: String)
        case keyCreationFailed(underlying: any Error)
        /// The blob is not a key this device's Secure Enclave can restore.
        case keyRestorationFailed(underlying: any Error)
        /// The key reported a public key that is not a valid P-256 point.
        case invalidPublicKey(JWKError)
    }

    extension SecureEnclaveError: CustomStringConvertible {
        public var description: String {
            switch self {
            case .unavailable:
                return "the Secure Enclave is not available on this device"
            case .accessControlCreationFailed(let description):
                return "could not create access control for a Secure Enclave key: \(description)"
            case .keyCreationFailed(let underlying):
                return "could not create a Secure Enclave key: \(underlying)"
            case .keyRestorationFailed(let underlying):
                return "could not restore a Secure Enclave key from its data representation: \(underlying)"
            case .invalidPublicKey(let error):
                return "Secure Enclave key reported an unusable public key: \(error)"
            }
        }
    }

    /// Signs ES256 with a P-256 key that lives in the Secure Enclave.
    ///
    /// The private key never leaves the enclave. ``dataRepresentation`` is an encrypted reference
    /// that only the same device can turn back into a key; storing it is the caller's job.
    public struct SecureEnclaveSigner: Signer {
        public typealias Algorithm = ES256

        public let keyID: KeyID?
        public let publicKey: ECPublicKey<P256Curve>
        private let key: any SecureEnclaveSigningKey

        /// The opaque, device-bound blob from which ``init(dataRepresentation:keyID:)`` restores
        /// this key.
        public var dataRepresentation: Data {
            key.dataRepresentation
        }

        init(key: any SecureEnclaveSigningKey, keyID: KeyID?) throws(SecureEnclaveError) {
            do {
                publicKey = try ECPublicKey(x963Representation: key.x963PublicKey)
            } catch {
                throw .invalidPublicKey(error)
            }
            self.key = key
            self.keyID = keyID
        }

        /// Creates a new key in the Secure Enclave.
        ///
        /// - Parameters:
        ///   - accessibility: When the key may be used. See ``SecureEnclaveAccessibility``.
        ///   - flags: Further requirements, such as `.biometryCurrentSet` or `.userPresence`.
        ///     `.privateKeyUsage` is always included.
        public static func generate(
            accessibility: SecureEnclaveAccessibility,
            flags: SecAccessControlCreateFlags = [],
            keyID: KeyID? = nil
        ) throws(SecureEnclaveError) -> SecureEnclaveSigner {
            #if DEBUG && targetEnvironment(simulator)
                return try SecureEnclaveSigner(key: SimulatorSoftwareKey(key: P256.Signing.PrivateKey()), keyID: keyID)
            #else
                guard SecureEnclave.isAvailable else {
                    throw .unavailable
                }
                var accessControlError: Unmanaged<CFError>?
                guard
                    let accessControl = SecAccessControlCreateWithFlags(
                        nil,
                        accessibility.protection,
                        flags.union(.privateKeyUsage),
                        &accessControlError
                    )
                else {
                    var description = "unknown error"
                    if let error = accessControlError?.takeRetainedValue() {
                        description = String(describing: error)
                    }
                    throw .accessControlCreationFailed(description: description)
                }
                let key: SecureEnclave.P256.Signing.PrivateKey
                do {
                    key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
                } catch {
                    throw .keyCreationFailed(underlying: error)
                }
                return try SecureEnclaveSigner(key: key, keyID: keyID)
            #endif
        }

        /// Restores a key from the blob returned by ``dataRepresentation``.
        public init(dataRepresentation: Data, keyID: KeyID? = nil) throws(SecureEnclaveError) {
            #if DEBUG && targetEnvironment(simulator)
                let key: P256.Signing.PrivateKey
                do {
                    key = try P256.Signing.PrivateKey(rawRepresentation: dataRepresentation)
                } catch {
                    throw .keyRestorationFailed(underlying: error)
                }
                try self.init(key: SimulatorSoftwareKey(key: key), keyID: keyID)
            #else
                guard SecureEnclave.isAvailable else {
                    throw .unavailable
                }
                let key: SecureEnclave.P256.Signing.PrivateKey
                do {
                    key = try SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: dataRepresentation)
                } catch {
                    throw .keyRestorationFailed(underlying: error)
                }
                try self.init(key: key, keyID: keyID)
            #endif
        }

        public func sign(_ message: Data) async throws(SigningError) -> Signature<ES256> {
            let raw: Data
            do {
                raw = try key.rawSignature(for: message)
            } catch {
                throw .keyOperationFailed(algorithm: Algorithm.identifier, underlying: error)
            }
            do {
                return try Signature(rawRepresentation: raw)
            } catch {
                throw .invalidSignature(error)
            }
        }
    }
#endif
