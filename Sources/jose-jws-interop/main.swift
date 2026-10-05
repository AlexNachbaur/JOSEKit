// Answers a challenge from `interop/closed-loop.mjs` so that the Node counterpart can check JWSs
// produced by JOSEJWS, and can check this package's verdicts on JWSs the counterpart made. Reads
// the challenge as JSON on stdin and writes the response as JSON on stdout. Not part of the
// library; see `scripts/interop.sh`.

import Foundation
import JOSECore
import JOSEJWK
import JOSEJWS

struct Challenge: Decodable {
    struct HMACKey: Decodable {
        let algorithm: String
        let jwk: String
    }
    struct VerifyCase: Decodable {
        let algorithm: String
        let jwk: String
        let serialization: String
        let token: String
    }

    /// Hex-encoded payload for the ordinary tokens.
    let payload: String
    /// UTF-8 payload for the RFC 7797 tokens.
    let unencodedPayload: String
    let hmacKeys: [HMACKey]
    /// JWSs made by the counterpart, some valid and some not, for this package to judge.
    let verify: [VerifyCase]
}

struct Response: Encodable {
    struct Produced: Encodable {
        let algorithm: String
        /// The verification key: a public JWK, or for HMAC the secret JWK from the challenge.
        let jwk: String
        let compact: String
        let compactDetached: String
        let flattened: String
        let general: String
        /// The key that made the second signature in `general`.
        let generalSecondJwk: String
        let unencodedDetached: String
        let customHeader: String
    }
    struct Verdict: Encodable {
        let accepted: Bool
        let payload: String?
    }

    var produced: [Produced] = []
    var verdicts: [Verdict] = []
}

struct InteropError: Error, CustomStringConvertible {
    let description: String
}

struct LevelHeader: HeaderParameters {
    static let criticalParameterNames: Set<String> = ["urn:example:must"]
    var level: Int
    var must: String

    enum CodingKeys: String, CodingKey {
        case level = "urn:example:level"
        case must = "urn:example:must"
    }
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

func text(_ data: Data) -> String {
    String(decoding: data, as: UTF8.self)
}

typealias Plain = JWS<EmptyHeaderParameters>

let challenge = try JSONDecoder().decode(Challenge.self, from: FileHandle.standardInput.readDataToEndOfFile())
let payload = try bytes(fromHex: challenge.payload)
let unencodedPayload = Data(challenge.unencodedPayload.utf8)

let secondKey = try ECPrivateKey<P256Curve>()
let secondSigner = try ECDSASigner(privateKey: secondKey, keyID: "second")
let secondJWK = text(try JWK(.p256(secondKey.publicKey)).jsonRepresentation())

func produce<S: Signer>(_ signer: S, jwk: String) async throws -> Response.Produced {
    let signed = try await Plain.sign(payload, with: signer, header: JWSHeaderParameters(type: "example+jws"))
    let both = try await signed.adding(signatureWith: secondSigner, header: JWSHeaderParameters())
    let unencoded = try await Plain.sign(unencodedPayload, with: signer, payloadEncoding: .unencoded)
    let custom = try await JWS<LevelHeader>.sign(
        payload,
        with: signer,
        header: JWSHeaderParameters(custom: LevelHeader(level: 7, must: "understood"))
    )
    return Response.Produced(
        algorithm: S.Algorithm.identifier.rawValue,
        jwk: jwk,
        compact: try signed.compactSerialization(),
        compactDetached: try signed.compactSerialization(detached: true),
        flattened: text(try signed.flattenedJSONSerialization()),
        general: text(try both.generalJSONSerialization()),
        generalSecondJwk: secondJWK,
        unencodedDetached: text(try unencoded.flattenedJSONSerialization(detached: true)),
        customHeader: try custom.compactSerialization()
    )
}

func publicJSON(_ key: JWK.Key) throws -> String {
    text(try JWK(key).jsonRepresentation())
}

var response = Response()

let p256 = try ECPrivateKey<P256Curve>()
response.produced.append(
    try await produce(try ECDSASigner(privateKey: p256, keyID: "p256"), jwk: try publicJSON(.p256(p256.publicKey)))
)
let p384 = try ECPrivateKey<P384Curve>()
response.produced.append(
    try await produce(try ECDSASigner(privateKey: p384, keyID: "p384"), jwk: try publicJSON(.p384(p384.publicKey)))
)
let p521 = try ECPrivateKey<P521Curve>()
response.produced.append(
    try await produce(try ECDSASigner(privateKey: p521, keyID: "p521"), jwk: try publicJSON(.p521(p521.publicKey)))
)
let edwards = try Ed25519PrivateKey()
let edwardsJWK = try publicJSON(.ed25519(edwards.publicKey))
response.produced.append(
    try await produce(try Ed25519Signer<JOSECore.Ed25519>(privateKey: edwards, keyID: "ed"), jwk: edwardsJWK)
)
response.produced.append(try await produce(try Ed25519Signer<EdDSA>(privateKey: edwards, keyID: "ed"), jwk: edwardsJWK))

for key in challenge.hmacKeys {
    let jwk = try SymmetricJWK(json: Data(key.jwk.utf8))
    switch key.algorithm {
    case "HS256":
        response.produced.append(try await produce(try HMACSigner<HS256>(jwk: jwk), jwk: key.jwk))
    case "HS384":
        response.produced.append(try await produce(try HMACSigner<HS384>(jwk: jwk), jwk: key.jwk))
    case "HS512":
        response.produced.append(try await produce(try HMACSigner<HS512>(jwk: jwk), jwk: key.jwk))
    default:
        throw InteropError(description: "unsupported HMAC algorithm \(key.algorithm)")
    }
}

func verifier(algorithm: String, jwk: String) throws -> AnyVerifier {
    let json = Data(jwk.utf8)
    switch algorithm {
    case "ES256":
        return try ES256.verifier(for: try JWK(json: json))
    case "ES384":
        return try ES384.verifier(for: try JWK(json: json))
    case "ES512":
        return try ES512.verifier(for: try JWK(json: json))
    case "Ed25519":
        return try JOSECore.Ed25519.verifier(for: try JWK(json: json))
    case "EdDSA":
        return try EdDSA.verifier(for: try JWK(json: json))
    case "HS256":
        return AnyVerifier(try HMACVerifier<HS256>(jwk: try SymmetricJWK(json: json)))
    case "HS384":
        return AnyVerifier(try HMACVerifier<HS384>(jwk: try SymmetricJWK(json: json)))
    case "HS512":
        return AnyVerifier(try HMACVerifier<HS512>(jwk: try SymmetricJWK(json: json)))
    default:
        throw InteropError(description: "unsupported algorithm \(algorithm)")
    }
}

for item in challenge.verify {
    let keys = VerificationKeys([try verifier(algorithm: item.algorithm, jwk: item.jwk)])
    do {
        let unverified: Plain.Unverified
        switch item.serialization {
        case "compact":
            unverified = try Plain.Unverified(compact: item.token)
        case "json":
            unverified = try Plain.Unverified(json: Data(item.token.utf8))
        default:
            throw InteropError(description: "unknown serialization \(item.serialization)")
        }
        let verified = try unverified.verify(with: keys)
        response.verdicts.append(Response.Verdict(accepted: true, payload: hex(verified.payload)))
    } catch is JWSError {
        response.verdicts.append(Response.Verdict(accepted: false, payload: nil))
    }
}

FileHandle.standardOutput.write(try JSONEncoder().encode(response))
