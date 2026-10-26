// Answers a challenge from `interop/jwt/closed-loop.mjs` so that the Node counterpart can check JWTs
// produced by JOSEJWT, and can check this package's verdicts on JWTs the counterpart made. Reads
// the challenge as JSON on stdin and writes the response as JSON on stdout. Not part of the
// library; see `scripts/interop.sh`.

import Foundation
import JOSECore
import JOSEJWK
import JOSEJWS
import JOSEJWT
import TestSupport

struct Challenge: Decodable {
    struct VerifyCase: Decodable {
        let algorithm: String
        let jwk: String
        let token: String
        let issuer: String?
        let audience: String?
        let typ: String?
        let clockTolerance: Int?
    }

    /// The instant, in seconds since 1970, that both sides treat as "now".
    let now: Double
    let hmacJwk: String
    /// JWTs made by the counterpart, some acceptable and some not, for this package to judge.
    let verify: [VerifyCase]
}

struct Response: Encodable {
    struct Produced: Encodable {
        let algorithm: String
        /// The verification key: a public JWK, or for HMAC the secret JWK from the challenge.
        let jwk: String
        /// Built with the claims builder.
        let built: String
        /// Built from typed custom claims with a custom header type.
        let typed: String
    }

    var produced: [Produced] = []
    var verdicts: [Bool] = []
}

struct AppClaims: Codable, Sendable {
    var scope: String
    var tenant: Int
    var roles: [String]
}

struct AppHeader: HeaderParameters {
    var nonce: String
}

let challenge = try Challenge(jsonFrom: .standardInput)
let now = Date(timeIntervalSince1970: challenge.now)
let clock = JWTClock.fixed(now)

func produce<S: Signer>(_ signer: S, jwk: String) async throws -> Response.Produced {
    let built = try await SignedJWT<EmptyClaims>.Signed(signingWith: signer, type: "at+jwt") {
        Issuer("https://issuer.example")
        Subject("user-123")
        Audience("https://api.example")
        ExpiresIn(.seconds(300), clock: clock)
        NotBefore(now)
        IssuedAt(clock: clock)
        JWTID("built-1")
        Claim("scope", "read write")
        Claim("nested", ["flag": true, "list": [1, "two"]])
    }.compactSerialization()

    var claims = JWTClaims(
        issuer: "https://issuer.example",
        subject: "user-456",
        audience: Audience("https://api.example", "https://other.example"),
        expiration: NumericDate(now.addingTimeInterval(60)),
        custom: AppClaims(scope: "admin", tenant: 7, roles: ["a", "b"])
    )
    claims.additionalClaims["https://example.com/claim"] = "namespaced"
    let typed = try await JWT<AppClaims, AppHeader>.Signed(
        signing: claims,
        with: signer,
        header: JWSHeaderParameters(type: "JWT", custom: AppHeader(nonce: "n-1"))
    ).compactSerialization()
    return Response.Produced(algorithm: S.Algorithm.identifier.rawValue, jwk: jwk, built: built, typed: typed)
}

func publicJSON(_ key: JWK.Key) throws -> String {
    String(utf8: try JWK(key).jsonRepresentation())
}

var response = Response()

let p256 = try ECPrivateKey<P256Curve>()
response.produced.append(
    try await produce(try ECDSASigner(privateKey: p256, keyID: "p256"), jwk: try publicJSON(.p256(p256.publicKey)))
)
let edwards = try Ed25519PrivateKey()
response.produced.append(
    try await produce(
        try Ed25519Signer<JOSECore.Ed25519>(privateKey: edwards, keyID: "ed"),
        jwk: try publicJSON(.ed25519(edwards.publicKey))
    )
)
let rsa = try RSAPrivateKey()
let rsaJWK = try publicJSON(.rsa(rsa.publicKey))
response.produced.append(try await produce(try RSASigner<RS256>(privateKey: rsa, keyID: "rsa"), jwk: rsaJWK))
response.produced.append(try await produce(try RSASigner<PS256>(privateKey: rsa, keyID: "rsa"), jwk: rsaJWK))
response.produced.append(
    try await produce(
        try HMACSigner<HS256>(jwk: try SymmetricJWK(json: Data(challenge.hmacJwk.utf8))),
        jwk: challenge.hmacJwk
    )
)

func verifier(algorithm: String, jwk: String) throws -> AnyVerifier {
    let json = Data(jwk.utf8)
    if let named = JWSAlgorithm.allCases.first(where: { $0.identifier.rawValue == algorithm }) {
        return try named.verifier(for: try JWK(json: json))
    }
    switch algorithm {
    case "HS256":
        return AnyVerifier(try HMACVerifier<HS256>(jwk: try SymmetricJWK(json: json)))
    default:
        throw FixtureError(description: "unsupported algorithm \(algorithm)")
    }
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
    var type = JWTValidationPolicy.TypeRule.unchecked
    if let expected = item.typ {
        type = .exactly(MediaType(rawValue: expected))
    }
    // jose does not require `exp`; the policy matches that so that the verdicts are comparable.
    let policy = JWTValidationPolicy(
        issuer: issuer,
        audience: audience,
        type: type,
        requiresExpiration: false,
        leeway: .seconds(item.clockTolerance ?? 0),
        clock: clock
    )
    let keys = VerificationKeys([try verifier(algorithm: item.algorithm, jwk: item.jwk)])
    do {
        _ = try await SimpleJWT.Unverified(compact: item.token).verify(with: keys).validate(policy)
        response.verdicts.append(true)
    } catch is JWTError {
        response.verdicts.append(false)
    } catch is JWTValidationError {
        response.verdicts.append(false)
    }
}

try response.writeJSON(to: .standardOutput)
