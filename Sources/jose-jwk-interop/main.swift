// Answers a challenge from `interop/jwk/closed-loop.mjs` so that the Node counterpart can check keys,
// thumbprints and signatures produced by JOSEJWK, and can check this package's verdicts on
// signatures the counterpart made. Reads the challenge as JSON on stdin and writes the response
// as JSON on stdout. Not part of the library; see `scripts/interop.sh`.

import Foundation
import JOSECore
import JOSEJWK
import TestSupport

struct Challenge: Decodable {
    struct HMACCase: Decodable {
        let algorithm: String
        let jwk: String
        let message: String
    }
    struct VerifyCase: Decodable {
        let algorithm: String
        let jwk: String
        let message: String
        let signature: String
    }

    /// Hex-encoded messages for each generated key to sign.
    let messages: [String]
    let hmac: [HMACCase]
    /// Signatures made by the counterpart, some valid and some not, for this package to judge.
    let verify: [VerifyCase]
}

struct Response: Encodable {
    struct SignatureCase: Encodable {
        let algorithm: String
        let message: String
        let signature: String
    }
    struct Key: Encodable {
        let curve: String
        let publicJwk: String
        let privateJwk: String?
        let thumbprints: [String: String]
        let thumbprintUris: [String: String]
        var signatures: [SignatureCase] = []
    }

    var keys: [Key] = []
    var hmac: [String] = []
    var verdicts: [Bool] = []
    /// Whether a key in this machine's Secure Enclave was among `keys`.
    var usedSecureEnclave = false
}

let hashes: [(String, JWKThumbprint.HashAlgorithm)] = [("sha256", .sha256), ("sha384", .sha384), ("sha512", .sha512)]

func describe(curve: String, publicJWK: JWK, privateJWK: PrivateJWK?) throws -> Response.Key {
    var thumbprints: [String: String] = [:]
    var uris: [String: String] = [:]
    for (name, hash) in hashes {
        let thumbprint = try publicJWK.thumbprint(using: hash)
        thumbprints[name] = thumbprint.base64URLEncoded
        uris[name] = thumbprint.uri
    }
    var privateJSON: String?
    if let privateJWK {
        privateJSON = String(decoding: try privateJWK.jsonRepresentation(), as: UTF8.self)
    }
    return Response.Key(
        curve: curve,
        publicJwk: String(decoding: try publicJWK.jsonRepresentation(), as: UTF8.self),
        privateJwk: privateJSON,
        thumbprints: thumbprints,
        thumbprintUris: uris
    )
}

func sign<S: Signer>(_ messages: [Data], with signer: S, into key: inout Response.Key) async throws {
    for message in messages {
        let signature = try await signer.sign(message)
        key.signatures.append(
            Response.SignatureCase(
                algorithm: S.Algorithm.identifier.rawValue,
                message: message.hex,
                signature: signature.rawRepresentation.hex
            )
        )
    }
}

func ecdsaKey<Curve: ECDSACurve>(
    _ curve: Curve.Type,
    wrap: (ECPrivateKey<Curve>) -> PrivateJWK.Key,
    publicWrap: (ECPublicKey<Curve>) -> JWK.Key,
    messages: [Data]
) async throws -> Response.Key {
    let privateKey = try ECPrivateKey<Curve>()
    var key = try describe(
        curve: Curve.name,
        publicJWK: JWK(publicWrap(privateKey.publicKey)),
        privateJWK: PrivateJWK(wrap(privateKey))
    )
    try await sign(messages, with: try ECDSASigner(privateKey: privateKey), into: &key)
    return key
}

func verdict<V: Verifier>(_ verifier: V, _ item: Challenge.VerifyCase) async throws -> Bool {
    let signature: Signature<V.Algorithm>
    do {
        signature = try Signature(rawRepresentation: try Data(hex: item.signature))
    } catch is SignatureError {
        return false
    }
    do {
        try await verifier.verify(signature, for: try Data(hex: item.message))
        return true
    } catch VerificationError.signatureMismatch {
        return false
    }
}

let challenge = try Challenge(jsonFrom: .standardInput)
let messages = try challenge.messages.map { try Data(hex: $0) }
var response = Response()

for _ in 0..<3 {
    response.keys.append(
        try await ecdsaKey(P256Curve.self, wrap: { .p256($0) }, publicWrap: { .p256($0) }, messages: messages)
    )
    response.keys.append(
        try await ecdsaKey(P384Curve.self, wrap: { .p384($0) }, publicWrap: { .p384($0) }, messages: messages)
    )
    response.keys.append(
        try await ecdsaKey(P521Curve.self, wrap: { .p521($0) }, publicWrap: { .p521($0) }, messages: messages)
    )

    let edwards = try Ed25519PrivateKey()
    var key = try describe(
        curve: Ed25519PublicKey.curveName,
        publicJWK: JWK(.ed25519(edwards.publicKey)),
        privateJWK: PrivateJWK(.ed25519(edwards))
    )
    try await sign(messages, with: try Ed25519Signer<JOSECore.Ed25519>(privateKey: edwards), into: &key)
    try await sign(messages, with: try Ed25519Signer<EdDSA>(privateKey: edwards), into: &key)
    response.keys.append(key)
}

for _ in 0..<2 {
    let rsa = try RSAPrivateKey()
    var key = try describe(curve: "RSA", publicJWK: JWK(.rsa(rsa.publicKey)), privateJWK: PrivateJWK(.rsa(rsa)))
    try await sign(messages, with: try RSASigner<RS256>(privateKey: rsa), into: &key)
    try await sign(messages, with: try RSASigner<RS384>(privateKey: rsa), into: &key)
    try await sign(messages, with: try RSASigner<RS512>(privateKey: rsa), into: &key)
    try await sign(messages, with: try RSASigner<PS256>(privateKey: rsa), into: &key)
    try await sign(messages, with: try RSASigner<PS384>(privateKey: rsa), into: &key)
    try await sign(messages, with: try RSASigner<PS512>(privateKey: rsa), into: &key)
    response.keys.append(key)
}

#if canImport(CryptoKit)
    // Where this machine has a usable Secure Enclave, put a hardware key through the same checks.
    do {
        let signer = try SecureEnclaveSigner.generate(accessibility: .whenUnlockedThisDeviceOnly)
        var key = try describe(curve: P256Curve.name, publicJWK: JWK(.p256(signer.publicKey)), privateJWK: nil)
        try await sign(messages, with: signer, into: &key)
        response.keys.append(key)
        response.usedSecureEnclave = true
    } catch let error as SecureEnclaveError {
        FileHandle.standardError.write(Data("note: Secure Enclave not used: \(error)\n".utf8))
    }
#endif

for item in challenge.hmac {
    let jwk = try SymmetricJWK(json: Data(item.jwk.utf8))
    let message = try Data(hex: item.message)
    switch item.algorithm {
    case "HS256":
        response.hmac.append(try await HMACSigner<HS256>(jwk: jwk).sign(message).rawRepresentation.hex)
    case "HS384":
        response.hmac.append(try await HMACSigner<HS384>(jwk: jwk).sign(message).rawRepresentation.hex)
    case "HS512":
        response.hmac.append(try await HMACSigner<HS512>(jwk: jwk).sign(message).rawRepresentation.hex)
    default:
        throw FixtureError(description: "unsupported HMAC algorithm \(item.algorithm)")
    }
}

for item in challenge.verify {
    let jwk = try JWK(json: Data(item.jwk.utf8))
    switch item.algorithm {
    case "ES256":
        response.verdicts.append(try await verdict(try ECDSAVerifier<P256Curve>(jwk: jwk), item))
    case "ES384":
        response.verdicts.append(try await verdict(try ECDSAVerifier<P384Curve>(jwk: jwk), item))
    case "ES512":
        response.verdicts.append(try await verdict(try ECDSAVerifier<P521Curve>(jwk: jwk), item))
    case "Ed25519":
        response.verdicts.append(try await verdict(try Ed25519Verifier<JOSECore.Ed25519>(jwk: jwk), item))
    case "EdDSA":
        response.verdicts.append(try await verdict(try Ed25519Verifier<EdDSA>(jwk: jwk), item))
    case "RS256":
        response.verdicts.append(try await verdict(try RSAVerifier<RS256>(jwk: jwk), item))
    case "RS384":
        response.verdicts.append(try await verdict(try RSAVerifier<RS384>(jwk: jwk), item))
    case "RS512":
        response.verdicts.append(try await verdict(try RSAVerifier<RS512>(jwk: jwk), item))
    case "PS256":
        response.verdicts.append(try await verdict(try RSAVerifier<PS256>(jwk: jwk), item))
    case "PS384":
        response.verdicts.append(try await verdict(try RSAVerifier<PS384>(jwk: jwk), item))
    case "PS512":
        response.verdicts.append(try await verdict(try RSAVerifier<PS512>(jwk: jwk), item))
    default:
        throw FixtureError(description: "unsupported algorithm \(item.algorithm)")
    }
}

try response.writeJSON(to: .standardOutput)
