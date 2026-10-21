// Answers a challenge from `interop/jwt/closed-loop-encrypted.mjs` so that the Node counterpart can
// decrypt encrypted and nested JWTs produced by JOSEJWTEncrypted, and can check this package's
// verdicts on ones the counterpart made. Reads the challenge as JSON on stdin and writes the
// response as JSON on stdout. Not part of the library; see `scripts/interop.sh`.

import Foundation
import JOSECore
import JOSEJWE
import JOSEJWK
import JOSEJWS
import JOSEJWT
import JOSEJWTEncrypted

struct Challenge: Decodable {
    struct Recipient: Decodable {
        let algorithm: String
        let encryption: String
        /// The recipient's public JWK, or the shared symmetric JWK.
        let jwk: String
    }
    struct VerifyCase: Decodable {
        let algorithm: String
        /// The private or symmetric JWK to decrypt with.
        let jwk: String
        let token: String
        /// Present for nested tokens: the signer's public JWK (ES256).
        let signerJwk: String?
        let issuer: String?
        let audience: String?
    }

    let now: Double
    let recipients: [Recipient]
    let verify: [VerifyCase]
}

struct Response: Encodable {
    struct Produced: Encodable {
        let algorithm: String
        let encrypted: String
        let nested: String
        /// The public JWK of the key that signed the nested token's inner JWT.
        let signerJwk: String
    }

    var produced: [Produced] = []
    var verdicts: [Bool] = []
}

struct InteropError: Error, CustomStringConvertible {
    let description: String
}

let challenge = try JSONDecoder().decode(Challenge.self, from: FileHandle.standardInput.readDataToEndOfFile())
let now = Date(timeIntervalSince1970: challenge.now)

func decrypter(algorithm: String, jwk: String) throws -> AnyKeyDecrypter {
    let json = Data(jwk.utf8)
    switch algorithm {
    case "dir":
        return AnyKeyDecrypter(try DirectDecrypter(jwk: try SymmetricJWK(json: json)))
    case "A256KW":
        return AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(jwk: try SymmetricJWK(json: json)))
    case "ECDH-ES":
        return try ECDHES().decrypter(for: try PrivateJWK(json: json))
    case "RSA-OAEP-256":
        return AnyKeyDecrypter(try RSADecrypter<RSAOAEP256>(jwk: try PrivateJWK(json: json)))
    default:
        throw InteropError(description: "unsupported algorithm \(algorithm)")
    }
}

var response = Response()
let claims = try JWTClaims {
    Issuer("https://issuer.example")
    Subject("user-123")
    Audience("https://api.example")
    ExpiresIn(.seconds(300), clock: .fixed(now))
    IssuedAt(now)
    Claim("scope", "read write")
}
let signingKey = try ECPrivateKey<P256Curve>()
let signer = try ECDSASigner(privateKey: signingKey, keyID: "sig")
let signerJWK = String(decoding: try JWK(.p256(signingKey.publicKey)).jsonRepresentation(), as: UTF8.self)
/// Produces both token kinds through the public API, for one concrete recipient type and the
/// named content encryption.
func produce<R: KeyEncrypter>(_ recipient: R, algorithm: String, encryption: String) async throws -> Response.Produced {
    func make(_ contentEncryption: some ContentEncryptionAlgorithm) async throws -> Response.Produced {
        Response.Produced(
            algorithm: algorithm,
            encrypted: try await SimpleEncryptedJWT.Encrypted(
                encrypting: claims,
                to: recipient,
                using: contentEncryption
            ).compactSerialization(),
            nested: try await SimpleNestedJWT.Encrypted(
                signing: claims,
                signedBy: signer,
                encryptedTo: recipient,
                using: contentEncryption
            ).compactSerialization(),
            signerJwk: signerJWK
        )
    }
    switch encryption {
    case "A256GCM":
        return try await make(.a256gcm)
    case "A128CBC-HS256":
        return try await make(.a128cbcHS256)
    case "A256CBC-HS512":
        return try await make(.a256cbcHS512)
    default:
        throw InteropError(description: "unsupported content encryption \(encryption)")
    }
}

for recipient in challenge.recipients {
    let json = Data(recipient.jwk.utf8)
    let produced: Response.Produced
    switch recipient.algorithm {
    case "dir":
        produced = try await produce(
            try DirectEncrypter(jwk: try SymmetricJWK(json: json)),
            algorithm: recipient.algorithm,
            encryption: recipient.encryption
        )
    case "A256KW":
        produced = try await produce(
            try AESKeyWrapEncrypter<A256KW>(jwk: try SymmetricJWK(json: json)),
            algorithm: recipient.algorithm,
            encryption: recipient.encryption
        )
    case "ECDH-ES":
        produced = try await produce(
            try ECDHESEncrypter<ECDHES>(jwk: try JWK(json: json)),
            algorithm: recipient.algorithm,
            encryption: recipient.encryption
        )
    case "RSA-OAEP-256":
        produced = try await produce(
            try RSAEncrypter<RSAOAEP256>(jwk: try JWK(json: json)),
            algorithm: recipient.algorithm,
            encryption: recipient.encryption
        )
    default:
        throw InteropError(description: "unsupported algorithm \(recipient.algorithm)")
    }
    response.produced.append(produced)
}

for item in challenge.verify {
    var issuer = JWTValidationPolicy.IssuerRule.unchecked
    if let expected = item.issuer {
        issuer = .exactly(expected)
    }
    var audience = JWTValidationPolicy.AudienceRule.unchecked
    if let expected = item.audience {
        audience = .contains(expected)
    }
    // jose does not require `exp`; the policy matches that so that the verdicts are comparable.
    let policy = JWTValidationPolicy(
        issuer: issuer,
        audience: audience,
        type: .unchecked,
        requiresExpiration: false,
        clock: .fixed(now)
    )
    let keys = DecryptionKeys([try decrypter(algorithm: item.algorithm, jwk: item.jwk)])
    do {
        if let signerJwk = item.signerJwk {
            let verification = VerificationKeys([try ES256.verifier(for: try JWK(json: Data(signerJwk.utf8)))])
            _ = try await SimpleNestedJWT.Encrypted(compact: item.token).decrypt(with: keys).verify(with: verification)
                .validate(policy)
        } else {
            _ = try await SimpleEncryptedJWT.Encrypted(compact: item.token).decrypt(with: keys).validate(policy)
        }
        response.verdicts.append(true)
    } catch is EncryptedJWTError {
        response.verdicts.append(false)
    } catch is JWTError {
        response.verdicts.append(false)
    } catch is JWTValidationError {
        response.verdicts.append(false)
    }
}

FileHandle.standardOutput.write(try JSONEncoder().encode(response))
