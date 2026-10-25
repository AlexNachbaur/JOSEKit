#if canImport(P256K)
    import Foundation
    import JOSECore
    import JOSEJWK
    import P256K

    /// secp256k1 (SEC 2 §2.4.1), the curve of ES256K (RFC 8812 §3.1), on bitcoin-core's libsecp256k1.
    ///
    /// Its keys are ``JOSEJWK/ECPublicKey`` and ``JOSEJWK/ECPrivateKey``, as for the NIST curves, so
    /// ``JOSEJWK/ECDSASigner`` and ``JOSEJWK/ECDSAVerifier`` sign and verify ES256K with them. In a
    /// JWK they are ``JOSEJWK/JWK/Key/external(_:)`` keys; pass ``JOSEJWK/ExternalKeyType/secp256k1``
    /// as `keyTypes` to read them that way.
    public struct Secp256k1Curve: ECDSACurve, ExternalCurve {
        public typealias Algorithm = ES256K
        public static let name = "secp256k1"
        public static let coordinateByteCount = 32

        public init() {}

        public func isPointOnCurve(x963: Data) -> Bool {
            do {
                _ = try P256K.Signing.PublicKey(dataRepresentation: x963, format: .uncompressed)
                return true
            } catch {
                // libsecp256k1's only failure for a correctly sized buffer is a point off the curve.
                return false
            }
        }

        public func publicKeyX963(privateScalar: Data) -> Data? {
            do {
                return try P256K.Signing.PrivateKey(dataRepresentation: privateScalar, format: .uncompressed)
                    .publicKey.uncompressedRepresentation
            } catch {
                return nil
            }
        }

        public func generatePrivateScalar() -> Data {
            // The system generator is cryptographically secure on every platform Swift supports,
            // and stops the process rather than return predictable bytes. 32 random bytes fail to
            // be a scalar only when they are zero or not below the order, about one time in 2^128.
            var generator = SystemRandomNumberGenerator()
            while true {
                let candidate = Data(
                    (0..<Self.coordinateByteCount).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
                )
                if publicKeyX963(privateScalar: candidate) != nil {
                    return candidate
                }
            }
        }

        public func signingKey(privateScalar: Data) throws -> P256K.Signing.PrivateKey {
            try P256K.Signing.PrivateKey(dataRepresentation: privateScalar, format: .uncompressed)
        }

        public func verifyingKey(x963: Data) throws -> P256K.Signing.PublicKey {
            try P256K.Signing.PublicKey(dataRepresentation: x963, format: .uncompressed)
        }

        public func x963(of key: P256K.Signing.PublicKey) -> Data {
            key.uncompressedRepresentation
        }

        public func privateScalar(of key: P256K.Signing.PrivateKey) -> Data {
            key.dataRepresentation
        }

        /// Signs with an RFC 6979 nonce. libsecp256k1 always produces the low-S form.
        public func rawSignature(for message: Data, using key: P256K.Signing.PrivateKey) throws -> Data {
            key.signature(for: message).compactRepresentation
        }

        /// Checks a signature in either S form.
        ///
        /// libsecp256k1 accepts only low S (BIP 62), but RFC 8812 does not require it, and other
        /// ES256K signers, WebCrypto implementations among them, produce high S half the time. An
        /// ECDSA signature `(r, s)` is valid exactly when `(r, n - s)` is, so a high S is replaced
        /// by its low form before checking.
        public func isValid(rawSignature: Data, for message: Data, using key: P256K.Signing.PublicKey) -> Bool {
            do {
                let signature = try P256K.Signing.ECDSASignature(
                    compactRepresentation: RawECDSASignature(rawSignature: rawSignature).lowS
                )
                return key.isValidSignature(signature, for: message)
            } catch {
                // r or s is not below the order, so the bytes are not a signature at all.
                return false
            }
        }
    }

    /// A compact ECDSA signature `r || s`, split into its two scalars.
    struct RawECDSASignature {
        /// The order of secp256k1's base point, big-endian (SEC 2 §2.4.1).
        static let order: [UInt8] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
            0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
        ]
        /// `order / 2`, rounded down: the largest low S.
        static let halfOrder: [UInt8] = [
            0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x5D, 0x57, 0x6E, 0x73, 0x57, 0xA4, 0x50, 0x1D, 0xDF, 0xE9, 0x2F, 0x46, 0x68, 0x1B, 0x20, 0xA0,
        ]

        let r: [UInt8]
        let s: [UInt8]

        /// `rawSignature` is 64 bytes: ``JOSECore/Signature`` checks the length for ES256K.
        init(rawSignature: Data) {
            let bytes = [UInt8](rawSignature)
            r = Array(bytes.prefix(32))
            s = Array(bytes.suffix(32))
        }

        /// `r || s`, with `s` replaced by `order - s` when it is above half the order.
        ///
        /// An `s` that is not below the order is a malformed signature. Subtracting it wraps to
        /// zero (for `s = order`) or to a value above the order, which libsecp256k1 refuses either
        /// way, so it needs no case of its own.
        var lowS: Data {
            guard Self.halfOrder.lexicographicallyPrecedes(s) else {
                return Data(r + s)
            }
            return Data(r + Self.subtract(s, from: Self.order))
        }

        /// `minuend - subtrahend` for 32-byte big-endian numbers, modulo 2^256.
        private static func subtract(_ subtrahend: [UInt8], from minuend: [UInt8]) -> [UInt8] {
            var difference = [UInt8](repeating: 0, count: minuend.count)
            var borrow = 0
            for index in minuend.indices.reversed() {
                var digit = Int(minuend[index]) - Int(subtrahend[index]) - borrow
                borrow = digit < 0 ? 1 : 0
                digit += 256 * borrow
                difference[index] = UInt8(digit)
            }
            return difference
        }
    }

    extension ExternalKeyType where Self == ECKeyType<Secp256k1Curve> {
        /// secp256k1 EC keys, for `keyTypes`.
        public static var secp256k1: Self {
            ECKeyType()
        }
    }
#endif
