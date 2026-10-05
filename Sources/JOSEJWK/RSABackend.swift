import Foundation
import JOSECore

/// How the message digest is padded before the RSA operation.
public enum RSASignaturePadding: Sendable {
    /// RSASSA-PKCS1-v1_5, the `RS*` algorithms.
    case pkcs1v15
    /// RSASSA-PSS with MGF1 over the same hash and a salt as long as the hash output, the `PS*`
    /// algorithms (RFC 7518 §3.5).
    case pss
}

public enum RSASignatureHash: Sendable {
    case sha256
    case sha384
    case sha512
}

/// The hash used by RSAES-OAEP, for both the label hash and MGF1.
public enum RSAOAEPHash: Sendable {
    /// `RSA-OAEP` (RFC 7518 §4.3).
    case sha1
    /// `RSA-OAEP-256`.
    case sha256
}

// CryptoKit has no RSA. On Apple platforms the operations go to Security.framework, so that
// Apple apps do not have to build BoringSSL; everywhere else they go to swift-crypto's extras.
// The two implementations sit behind the same two types, and are held to the same fixtures.

#if canImport(Security)
    import Security

    /// `SecKey` is not declared `Sendable`. It is an immutable CoreFoundation object that Apple
    /// documents as safe to use from multiple threads, and nothing here mutates it after creation,
    /// so sharing it across isolation domains is sound.
    private struct SendableSecKey: @unchecked Sendable {
        let key: SecKey
    }

    private func describe(_ error: Unmanaged<CFError>?) -> String {
        guard let error else {
            return "unknown error"
        }
        return String(describing: error.takeRetainedValue())
    }

    private func makeSecKey(pkcs1DER: Data, keyClass: CFString) throws(JWKError) -> SendableSecKey {
        let attributes: [CFString: Any] = [
            kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeyClass: keyClass,
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateWithData(pkcs1DER as CFData, attributes as CFDictionary, &error) else {
            throw .invalidRSAKey(reason: describe(error))
        }
        return SendableSecKey(key: key)
    }

    private func secAlgorithm(padding: RSASignaturePadding, hash: RSASignatureHash) -> SecKeyAlgorithm {
        switch (padding, hash) {
        case (.pkcs1v15, .sha256):
            return .rsaSignatureMessagePKCS1v15SHA256
        case (.pkcs1v15, .sha384):
            return .rsaSignatureMessagePKCS1v15SHA384
        case (.pkcs1v15, .sha512):
            return .rsaSignatureMessagePKCS1v15SHA512
        case (.pss, .sha256):
            return .rsaSignatureMessagePSSSHA256
        case (.pss, .sha384):
            return .rsaSignatureMessagePSSSHA384
        case (.pss, .sha512):
            return .rsaSignatureMessagePSSSHA512
        }
    }

    private func oaepAlgorithm(_ hash: RSAOAEPHash) -> SecKeyAlgorithm {
        switch hash {
        case .sha1:
            return .rsaEncryptionOAEPSHA1
        case .sha256:
            return .rsaEncryptionOAEPSHA256
        }
    }

    struct RSABackendPublicKey: Sendable {
        private let wrapped: SendableSecKey

        init(pkcs1DER: Data) throws(JWKError) {
            wrapped = try makeSecKey(pkcs1DER: pkcs1DER, keyClass: kSecAttrKeyClassPublic)
        }

        func isValid(signature: Data, for message: Data, padding: RSASignaturePadding, hash: RSASignatureHash) -> Bool {
            var error: Unmanaged<CFError>?
            let isValid = SecKeyVerifySignature(
                wrapped.key,
                secAlgorithm(padding: padding, hash: hash),
                message as CFData,
                signature as CFData,
                &error
            )
            // The error only restates that verification failed; it is taken so that it is released.
            _ = error?.takeRetainedValue()
            return isValid
        }

        func encryptOAEP(_ plaintext: Data, hash: RSAOAEPHash) throws(JWKError) -> Data {
            var error: Unmanaged<CFError>?
            let algorithm = oaepAlgorithm(hash)
            guard let ciphertext = SecKeyCreateEncryptedData(wrapped.key, algorithm, plaintext as CFData, &error) else {
                throw .rsaEncryptionFailed(reason: describe(error))
            }
            return ciphertext as Data
        }
    }

    struct RSABackendPrivateKey: Sendable {
        private let wrapped: SendableSecKey

        init(pkcs1DER: Data) throws(JWKError) {
            wrapped = try makeSecKey(pkcs1DER: pkcs1DER, keyClass: kSecAttrKeyClassPrivate)
        }

        func signature(for message: Data, padding: RSASignaturePadding, hash: RSASignatureHash) throws -> Data {
            var error: Unmanaged<CFError>?
            let algorithm = secAlgorithm(padding: padding, hash: hash)
            guard let signature = SecKeyCreateSignature(wrapped.key, algorithm, message as CFData, &error) else {
                throw JWKError.invalidRSAKey(reason: "signing failed: \(describe(error))")
            }
            return signature as Data
        }

        func decryptOAEP(_ ciphertext: Data, hash: RSAOAEPHash) throws(JWKError) -> Data {
            var error: Unmanaged<CFError>?
            let algorithm = oaepAlgorithm(hash)
            guard let plaintext = SecKeyCreateDecryptedData(wrapped.key, algorithm, ciphertext as CFData, &error) else {
                // Taken so that it is released; its content is deliberately not reported.
                _ = error?.takeRetainedValue()
                throw .rsaDecryptionFailed
            }
            return plaintext as Data
        }

        /// Generates a key in memory (it is not stored in the keychain) and returns it as PKCS#1 DER.
        static func generatePKCS1DER(bitCount: Int) throws(JWKError) -> Data {
            let attributes: [CFString: Any] = [
                kSecAttrKeyType: kSecAttrKeyTypeRSA,
                kSecAttrKeySizeInBits: bitCount,
            ]
            var error: Unmanaged<CFError>?
            guard let key = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
                throw .invalidRSAKey(reason: "key generation failed: \(describe(error))")
            }
            guard let der = SecKeyCopyExternalRepresentation(key, &error) else {
                throw .invalidRSAKey(reason: "generated key could not be exported: \(describe(error))")
            }
            return der as Data
        }
    }

#else
    import Crypto
    import CryptoExtras

    private func rsaPadding(_ padding: RSASignaturePadding) -> _RSA.Signing.Padding {
        switch padding {
        case .pkcs1v15:
            return .insecurePKCS1v1_5
        case .pss:
            return .PSS
        }
    }

    private func oaepPadding(_ hash: RSAOAEPHash) -> _RSA.Encryption.Padding {
        switch hash {
        case .sha1:
            return .PKCS1_OAEP
        case .sha256:
            return .PKCS1_OAEP_SHA256
        }
    }

    struct RSABackendPublicKey: Sendable {
        private let key: _RSA.Signing.PublicKey
        // swift-crypto's RSA encryption key types are not `Sendable`, unlike its signing keys.
        // Rather than assert that they are safe to share, the DER is kept and the encryption key
        // is rebuilt for each operation; parsing it is negligible next to the RSA operation.
        private let der: Data

        init(pkcs1DER: Data) throws(JWKError) {
            do {
                key = try _RSA.Signing.PublicKey(derRepresentation: pkcs1DER)
                _ = try _RSA.Encryption.PublicKey(derRepresentation: pkcs1DER)
                der = pkcs1DER
            } catch {
                throw .invalidRSAKey(reason: String(describing: error))
            }
        }

        func isValid(signature: Data, for message: Data, padding: RSASignaturePadding, hash: RSASignatureHash) -> Bool {
            let rsaSignature = _RSA.Signing.RSASignature(rawRepresentation: signature)
            switch hash {
            case .sha256:
                return key.isValidSignature(rsaSignature, for: SHA256.hash(data: message), padding: rsaPadding(padding))
            case .sha384:
                return key.isValidSignature(rsaSignature, for: SHA384.hash(data: message), padding: rsaPadding(padding))
            case .sha512:
                return key.isValidSignature(rsaSignature, for: SHA512.hash(data: message), padding: rsaPadding(padding))
            }
        }

        func encryptOAEP(_ plaintext: Data, hash: RSAOAEPHash) throws(JWKError) -> Data {
            do {
                return try _RSA.Encryption.PublicKey(derRepresentation: der)
                    .encrypt(plaintext, padding: oaepPadding(hash))
            } catch {
                throw .rsaEncryptionFailed(reason: String(describing: error))
            }
        }
    }

    struct RSABackendPrivateKey: Sendable {
        private let key: _RSA.Signing.PrivateKey
        // See `RSABackendPublicKey.der`.
        private let der: Data

        init(pkcs1DER: Data) throws(JWKError) {
            do {
                key = try _RSA.Signing.PrivateKey(derRepresentation: pkcs1DER)
                _ = try _RSA.Encryption.PrivateKey(derRepresentation: pkcs1DER)
                der = pkcs1DER
            } catch {
                throw .invalidRSAKey(reason: String(describing: error))
            }
        }

        func signature(for message: Data, padding: RSASignaturePadding, hash: RSASignatureHash) throws -> Data {
            switch hash {
            case .sha256:
                return try key.signature(for: SHA256.hash(data: message), padding: rsaPadding(padding))
                    .rawRepresentation
            case .sha384:
                return try key.signature(for: SHA384.hash(data: message), padding: rsaPadding(padding))
                    .rawRepresentation
            case .sha512:
                return try key.signature(for: SHA512.hash(data: message), padding: rsaPadding(padding))
                    .rawRepresentation
            }
        }

        func decryptOAEP(_ ciphertext: Data, hash: RSAOAEPHash) throws(JWKError) -> Data {
            do {
                return try _RSA.Encryption.PrivateKey(derRepresentation: der)
                    .decrypt(ciphertext, padding: oaepPadding(hash))
            } catch {
                throw .rsaDecryptionFailed
            }
        }

        static func generatePKCS1DER(bitCount: Int) throws(JWKError) -> Data {
            do {
                return try _RSA.Signing.PrivateKey(keySize: .init(bitCount: bitCount)).derRepresentation
            } catch {
                throw .invalidRSAKey(reason: "key generation failed: \(error)")
            }
        }
    }
#endif
