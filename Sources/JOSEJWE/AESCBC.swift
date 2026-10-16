import Foundation

// CryptoKit has no AES-CBC. On Apple platforms it comes from CommonCrypto, which is part of the
// operating system; elsewhere from swift-crypto's extras. Both use PKCS#7 padding, which is what
// RFC 7518 §5.2.2 specifies.

struct AESCBCError: Error, CustomStringConvertible {
    let description: String
}

#if canImport(CommonCrypto)
    import CommonCrypto

    struct AESCBC {
        private init() {}

        static func encrypt(_ plaintext: Data, key: Data, iv: Data) throws -> Data {
            try crypt(CCOperation(kCCEncrypt), plaintext, key: key, iv: iv)
        }

        static func decrypt(_ ciphertext: Data, key: Data, iv: Data) throws -> Data {
            try crypt(CCOperation(kCCDecrypt), ciphertext, key: key, iv: iv)
        }

        private static func crypt(_ operation: CCOperation, _ input: Data, key: Data, iv: Data) throws -> Data {
            guard iv.count == kCCBlockSizeAES128 else {
                throw AESCBCError(description: "AES-CBC needs a 16-byte IV; got \(iv.count)")
            }
            let inputBytes = [UInt8](input)
            let keyBytes = [UInt8](key)
            let ivBytes = [UInt8](iv)
            var output = [UInt8](repeating: 0, count: inputBytes.count + kCCBlockSizeAES128)
            var outputCount = 0
            let status = CCCrypt(
                operation,
                CCAlgorithm(kCCAlgorithmAES),
                CCOptions(kCCOptionPKCS7Padding),
                keyBytes,
                keyBytes.count,
                ivBytes,
                inputBytes,
                inputBytes.count,
                &output,
                output.count,
                &outputCount
            )
            guard status == kCCSuccess else {
                throw AESCBCError(description: "CommonCrypto AES-CBC failed with status \(status)")
            }
            return Data(output.prefix(outputCount))
        }
    }

#else
    import Crypto
    import CryptoExtras

    struct AESCBC {
        private init() {}

        static func encrypt(_ plaintext: Data, key: Data, iv: Data) throws -> Data {
            try AES._CBC.encrypt(plaintext, using: SymmetricKey(data: key), iv: try AES._CBC.IV(ivBytes: [UInt8](iv)))
        }

        static func decrypt(_ ciphertext: Data, key: Data, iv: Data) throws -> Data {
            try AES._CBC.decrypt(ciphertext, using: SymmetricKey(data: key), iv: try AES._CBC.IV(ivBytes: [UInt8](iv)))
        }
    }
#endif
