import Foundation

// PKCS#1 (RFC 8017 Appendix A.1) encoding of RSA keys. Both RSA backends take keys in this form,
// and it is how keys commonly arrive from other systems.
//
//     RSAPublicKey  ::= SEQUENCE { modulus INTEGER, publicExponent INTEGER }
//     RSAPrivateKey ::= SEQUENCE { version INTEGER (0), modulus, publicExponent,
//                                  privateExponent, prime1, prime2, exponent1, exponent2,
//                                  coefficient }

/// The values of an RSA private key, each as an unsigned big-endian integer with no leading zeros.
struct RSAPrivateKeyComponents: Sendable {
    var modulus: Data
    var publicExponent: Data
    var privateExponent: Data
    var prime1: Data
    var prime2: Data
    var exponent1: Data
    var exponent2: Data
    var coefficient: Data
}

extension RSAPrivateKeyComponents {
    /// Reads a PKCS#1 `RSAPrivateKey`.
    init(pkcs1DER der: Data) throws(JWKError) {
        var reader = try DERReader.wholeSequence(der, "key")
        let version = try reader.readUnsignedInteger("version")
        guard version == Data([0x00]) else {
            // Version 1 means more than two primes, which RFC 7518 expresses with "oth".
            throw .unsupportedRSAPrivateKey(reason: "PKCS#1 version \(version.map(String.init).joined()) (multi-prime)")
        }
        self.init(
            modulus: try reader.readUnsignedInteger("modulus"),
            publicExponent: try reader.readUnsignedInteger("publicExponent"),
            privateExponent: try reader.readUnsignedInteger("privateExponent"),
            prime1: try reader.readUnsignedInteger("prime1"),
            prime2: try reader.readUnsignedInteger("prime2"),
            exponent1: try reader.readUnsignedInteger("exponent1"),
            exponent2: try reader.readUnsignedInteger("exponent2"),
            coefficient: try reader.readUnsignedInteger("coefficient")
        )
        try reader.finish("the last value")
    }

    /// The PKCS#1 `RSAPrivateKey`.
    var pkcs1DER: Data {
        var writer = DERWriter()
        writer.writeUnsignedInteger(Data([0x00]))
        for value in [
            modulus, publicExponent, privateExponent, prime1, prime2, exponent1, exponent2, coefficient,
        ] {
            writer.writeUnsignedInteger(value)
        }
        return writer.sequence()
    }
}
