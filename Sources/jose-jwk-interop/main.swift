// Answers a challenge from `interop/closed-loop.mjs` so that the Node counterpart can check keys,
// thumbprints and signatures produced by JOSEJWK, and can check this package's verdicts on
// signatures the counterpart made. Reads the challenge as JSON on stdin and writes the response
// as JSON on stdout. Not part of the library; see `scripts/interop.sh`.

import Foundation
import JOSECore
import JOSEJWK

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

struct InteropError: Error, CustomStringConvertible {
    let description: String
}

func bytes(fromHex hex: String) throws -> Data {
    let digits = Array(hex.utf8)
    guard digits.count.isMultiple(of: 2) else {
        throw InteropError(description: "hex string has odd length \(digits.count)")
    }
    var output = Data(capacity: digits.count / 2)
    for index in stride(from: 0, to: digits.count, by: 2) {
        guard let byte = UInt8(String(decoding: digits[index..<(index + 2)], as: UTF8.self), radix: 16) else {
            throw InteropError(description: "invalid hex at offset \(index)")
        }
        output.append(byte)
    }
    return output
}

func hex(_ data: Data) -> String {
    data.map { byte in
        let digits = String(byte, radix: 16)
        if digits.count == 1 {
            return "0" + digits
        }
        return digits
    }
    .joined()
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
                message: hex(message),
                signature: hex(signature.rawRepresentation)
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

func verdict<V: Verifier>(_ verifier: V, _ item: Challenge.VerifyCase) throws -> Bool {
    let signature: Signature<V.Algorithm>
    do {
        signature = try Signature(rawRepresentation: try bytes(fromHex: item.signature))
    } catch is SignatureError {
        return false
    }
    do {
        try verifier.verify(signature, for: try bytes(fromHex: item.message))
        return true
    } catch VerificationError.signatureMismatch {
        return false
    }
}

let challenge = try JSONDecoder().decode(Challenge.self, from: FileHandle.standardInput.readDataToEndOfFile())
let messages = try challenge.messages.map { try bytes(fromHex: $0) }
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
    let message = try bytes(fromHex: item.message)
    switch item.algorithm {
    case "HS256":
        response.hmac.append(hex(try await HMACSigner<HS256>(jwk: jwk).sign(message).rawRepresentation))
    case "HS384":
        response.hmac.append(hex(try await HMACSigner<HS384>(jwk: jwk).sign(message).rawRepresentation))
    case "HS512":
        response.hmac.append(hex(try await HMACSigner<HS512>(jwk: jwk).sign(message).rawRepresentation))
    default:
        throw InteropError(description: "unsupported HMAC algorithm \(item.algorithm)")
    }
}

for item in challenge.verify {
    let jwk = try JWK(json: Data(item.jwk.utf8))
    switch item.algorithm {
    case "ES256":
        response.verdicts.append(try verdict(try ECDSAVerifier<P256Curve>(jwk: jwk), item))
    case "ES384":
        response.verdicts.append(try verdict(try ECDSAVerifier<P384Curve>(jwk: jwk), item))
    case "ES512":
        response.verdicts.append(try verdict(try ECDSAVerifier<P521Curve>(jwk: jwk), item))
    case "Ed25519":
        response.verdicts.append(try verdict(try Ed25519Verifier<JOSECore.Ed25519>(jwk: jwk), item))
    case "EdDSA":
        response.verdicts.append(try verdict(try Ed25519Verifier<EdDSA>(jwk: jwk), item))
    default:
        throw InteropError(description: "unsupported algorithm \(item.algorithm)")
    }
}

FileHandle.standardOutput.write(try JSONEncoder().encode(response))
