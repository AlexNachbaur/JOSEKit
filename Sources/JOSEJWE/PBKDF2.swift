import Foundation

// CryptoKit has no PBKDF2. On Apple platforms it comes from CommonCrypto; elsewhere from
// swift-crypto's extras. Both produce the PBKDF2 of RFC 8018 with HMAC as the PRF.

struct PBKDF2Error: Error, CustomStringConvertible {
    let description: String
}

/// The HMAC hash used as PBKDF2's pseudo-random function.
public enum PBKDF2Hash: Sendable {
    case sha256
    case sha384
    case sha512
}

#if canImport(CommonCrypto)
    import CommonCrypto

    struct PBKDF2 {
        private init() {}

        static func derive(password: Data, salt: Data, iterations: Int, hash: PBKDF2Hash, byteCount: Int) throws -> Data
        {
            let algorithm: CCPseudoRandomAlgorithm
            switch hash {
            case .sha256:
                algorithm = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256)
            case .sha384:
                algorithm = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA384)
            case .sha512:
                algorithm = CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA512)
            }
            let passwordBytes = [UInt8](password)
            let saltBytes = [UInt8](salt)
            var derived = [UInt8](repeating: 0, count: byteCount)
            let status = passwordBytes.withUnsafeBufferPointer { passwordBuffer in
                CCKeyDerivationPBKDF(
                    CCPBKDFAlgorithm(kCCPBKDF2),
                    passwordBuffer.baseAddress.map { UnsafeRawPointer($0).assumingMemoryBound(to: CChar.self) },
                    passwordBytes.count,
                    saltBytes,
                    saltBytes.count,
                    algorithm,
                    UInt32(iterations),
                    &derived,
                    byteCount
                )
            }
            guard status == kCCSuccess else {
                throw PBKDF2Error(description: "CommonCrypto PBKDF2 failed with status \(status)")
            }
            return Data(derived)
        }
    }

#else
    import Crypto
    import CryptoExtras

    struct PBKDF2 {
        private init() {}

        static func derive(password: Data, salt: Data, iterations: Int, hash: PBKDF2Hash, byteCount: Int) throws -> Data
        {
            let function: KDF.Insecure.PBKDF2.HashFunction
            switch hash {
            case .sha256:
                function = .sha256
            case .sha384:
                function = .sha384
            case .sha512:
                function = .sha512
            }
            let key = try KDF.Insecure.PBKDF2.deriveKey(
                from: password,
                salt: salt,
                using: function,
                outputByteCount: byteCount,
                unsafeUncheckedRounds: iterations
            )
            return key.withUnsafeBytes { Data($0) }
        }
    }
#endif
