# JOSE packages — design proposal

Status: decisions in §5 are settled; where they differ from the text above them, §5 wins.
Code samples for packages other than jose-core show intended API shape and have not been compiled.

## 1. Packages and dependency graph

```
jose-core ──► jose-jwk ──┬─► jose-jws ──┬─► jose-jwt
                         └─► jose-jwe ──┘
```

| Package    | Module     | Depends on                 | Owns |
|------------|------------|----------------------------|------|
| jose-core  | `JOSECore` | nothing                    | base64url, strict JSON, `JSONValue`, DER↔P1363, algorithm identifiers, shared header parameters |
| jose-jwk   | `JOSEJWK`  | core, CryptoKit/swift-crypto | typed keys, JWK/JWKS, RFC 7638 thumbprints, X9.63 parsing, signature algorithms, `Signer`/`Verifier`, Secure Enclave |
| jose-jws   | `JOSEJWS`  | jwk                        | JWS header, compact/JSON serialisations, verification type-states |
| jose-jwe   | `JOSEJWE`  | jwk                        | key-management and content-encryption algorithms, JWE serialisations |
| jose-jwt   | `JOSEJWT`  | jws (+ jwe, see D3)        | claims, claim builders, validation policy, nested JWTs |

Module names carry the `JOSE` prefix because a module named `JWK` containing a type named
`JWK` makes `JWK.Something` ambiguous at every use site, and Swift has no way to disambiguate.

`jose-core` has no crypto and therefore no dependencies on any platform. The others import
crypto through one shim:

```swift
#if canImport(CryptoKit)
import CryptoKit
#else
import Crypto   // apple/swift-crypto
#endif
```

D14 supersedes the five packages: they are now modules of one package in one repository, with
the same names and the same dependency graph between them.

## 2. Compile-time safety model

The goal is that the well-known JOSE failures are unrepresentable rather than checked.

### 2.1 Algorithms are types, and keys are bound to them

```swift
public protocol SignatureAlgorithm: Sendable {
    static var identifier: AlgorithmIdentifier { get }      // "ES256"
}
public struct ES256: SignatureAlgorithm { … }               // also ES384, ES512, EdDSA, HS256/384/512

public protocol Signer<Algorithm>: Sendable {
    associatedtype Algorithm: SignatureAlgorithm
    var keyID: KeyID? { get }
    func sign(_ input: some DataProtocol) async throws(SigningError) -> Signature<Algorithm>
}

public protocol Verifier<Algorithm>: Sendable {
    associatedtype Algorithm: SignatureAlgorithm
    var keyID: KeyID? { get }
    func verify(_ signature: Signature<Algorithm>, for input: some DataProtocol) throws(VerificationError)
}
```

Consequences:

- **`alg` cannot be set by the caller.** The header's `alg` is written from `Signer.Algorithm`.
  A header that disagrees with its key cannot be constructed.
- **`alg: none` does not exist.** No type conforms. A developer would have to write one.
- **Algorithm confusion is a type error.** The HS256 verifier takes a `SymmetricKey`; the ES256
  verifier takes `ECPublicKey<P256>`. Handing an EC or RSA public key to an HMAC verifier does
  not compile.
- **`Signature<ES256>` is always 64 bytes of P1363.** A DER signature is a different type
  (`DERECDSASignature`) and must be converted explicitly; the conversion is in `JOSECore`.
- **Custom algorithms** are a marker type plus a `Signer`/`Verifier` conformance. Nothing in the
  library needs to change or be registered globally.

### 2.2 Keys: curve and visibility in the type

```swift
public struct ECPublicKey<Curve: EllipticCurve>: Sendable, Hashable { … }   // P256, P384, P521
public struct ECPrivateKey<Curve: EllipticCurve>: Sendable { … }            // not Codable, not printable

public enum JWK: Sendable, Hashable, Codable {       // public material only
    case ec(AnyECPublicKey, JWKMetadata)
    case okp(OKPPublicKey, JWKMetadata)
    case rsa(RSAPublicKey, JWKMetadata)               // if RSA is in scope (D5)
}
public struct PrivateJWK: Sendable { … }              // separate type; explicit export only
public struct SymmetricJWK: Sendable { … }            // `oct`; never placed in a JWKSet for publishing
```

- A `JWKSet` and the `jwk` header parameter hold `JWK` — so a private or symmetric key cannot be
  published by mistake; there is no value of the right type to put there.
- Private types have a redacted `description` and no `Codable` conformance. Export is a named
  method (`exportPrivateJWK()`).
- X9.63 import checks length **and** the `0x04` marker, then validates the point on the curve.
- `use`, `key_ops` and `alg` on a JWK are enforced when a verifier/decrypter is built from it.

### 2.3 RFC 7638 thumbprints

```swift
let thumbprint: JWKThumbprint<SHA256> = key.thumbprint()
thumbprint.base64URLEncoded
```

Each key type has a hand-written canonical form with members in a spelled-out order
(`crv`,`kty`,`x`,`y` for EC; `e`,`kty`,`n` for RSA; `crv`,`kty`,`x` for OKP), values passed through
the JSON string escaper. No runtime sorting, no `JSONEncoder`.

### 2.4 Verification is a type-state

```swift
let unverified = try JWS<MyHeader>.Unverified(compact: string)   // parsed, structurally valid
unverified.header                                                 // readable: needed for key selection
// unverified.payload                                             // does not exist
unverified.unverifiedPayload                                      // exists, and says what it is

let verified: JWS<MyHeader>.Verified = try unverified.verify(with: keys)
verified.payload
```

JWT adds a second state:

```swift
let token: JWT<MyClaims>.Validated = try JWT<MyClaims>
    .Unverified(compact: string)
    .verify(with: keys)                   // → JWT<MyClaims>.Verified   (signature good, claims unchecked)
    .validate(policy)                     // → JWT<MyClaims>.Validated  (exp/nbf/iss/aud checked)
```

Application code takes `JWT<MyClaims>.Validated` as its parameter type. An unverified or
unvalidated token cannot be passed to it.

The signature is always checked over the **received bytes** of the protected header and payload,
never over a re-encoding.

### 2.5 Choosing a key at verification time

The token's `alg` is only known at runtime, so the set of acceptable algorithms is defined by
which verifiers the caller supplies — there is no separate `algorithms: [...]` list to forget:

```swift
let keys = VerificationKeys {
    ES256.verifier(publicKey)             // typed: ECPublicKey<P256>
    EdDSA.verifier(edKey)
    try jwks.verifiers(allowing: ES256.self, ES384.self)
}
```

A token whose `alg` has no matching verifier fails with
`.noVerifierForAlgorithm("RS256", offered: ["ES256", "EdDSA"])`. `kid` narrows candidates when present.

### 2.6 Headers and claims: library-owned fields plus your type

```swift
public struct JWSHeader<Custom: HeaderParameters>: Sendable {
    public let algorithm: AlgorithmIdentifier      // read-only
    public var keyID: KeyID?
    public var type: MediaType?                    // typ
    public var contentType: MediaType?             // cty
    public var jwk: JWK?                           // public by construction
    public var custom: Custom                      // encoded at the same JSON level
}
public protocol HeaderParameters: Codable, Sendable {
    static var criticalParameters: Set<String> { get }   // default: []
}
```

`crit` is handled per RFC 7515 §4.1.11: a token listing a critical parameter that the `Custom`
type does not declare is rejected. `EmptyHeaderParameters` is the default.

Claims follow the same pattern:

```swift
public struct JWTClaims<Custom: Codable & Sendable>: Sendable {
    public var issuer: Issuer?
    public var subject: Subject?
    public var audience: Audience?                 // string-or-array handled once, here
    public var expiration: NumericDate?
    public var notBefore: NumericDate?
    public var issuedAt: NumericDate?
    public var jwtID: JWTID?
    public var custom: Custom
}
```

### 2.7 Building tokens

A plain initialiser is the primary API. The result builder is optional sugar over it:

```swift
let jwt = try await JWT.sign(with: signer, type: "at+jwt") {
    Issuer("https://issuer.example")
    Subject(userID)
    Audience("https://api.example")
    ExpiresIn(.minutes(5), clock: clock)
    IssuedAt(clock: clock)
    JWTID.random()
    Claim("scope", "read write")          // ad-hoc claim, JSONValue-backed
    MyClaims(tenant: tenant)              // typed custom claims
}
```

Duplicate registered claims in a builder are a compile error where the builder can express it
(D9), otherwise a thrown error naming the claim.

### 2.8 Validating claims

There is no default policy and no `validate()` with no arguments. Issuer and audience must be
stated, or explicitly waived:

```swift
let policy = JWTValidationPolicy(
    issuer: .exactly("https://issuer.example"),
    audience: .contains("https://api.example"),      // or .unchecked — visible in code review
    type: .exactly("at+jwt"),                        // RFC 8725 explicit typing
    clock: .system,                                  // injectable for tests
    leeway: .seconds(30)
)
```

### 2.9 Errors

Typed throws (`throws(JWSError)`) on the public API, one enum per layer, each case carrying the
field and the offending condition:

```swift
public enum Base64URLError: Error, Sendable {
    case invalidLength(count: Int)                   // 4n+1
    case invalidCharacter(UInt8, offset: Int)
    case misplacedPadding(offset: Int)
    case wrongPaddingLength(expected: Int, found: Int)
}
public enum JWTValidationError: Error, Sendable {
    case expired(expiration: NumericDate, now: NumericDate, leeway: Duration)
    case issuerMismatch(expected: String, found: String?)
    …
}
```

**One deliberate exception.** JWE decryption reports structural problems precisely but collapses
every cryptographic failure (key unwrap, tag mismatch) into a single `.decryptionFailed`.
Distinguishing them is a padding/unwrap oracle (RFC 7516 §11.5). This conflicts with the
"every error names its cause" rule and I think the rule should lose here — see D8.

## 3. Package contents

### jose-core
- `Base64URL`: unpadded output; strict input per the engineering rules (rejects 4n+1, interior
  `=`, wrong padding length, non-alphabet bytes, and non-zero trailing bits — D10).
- Strict JSON object reader that **rejects duplicate member names** (RFC 7515 §4 permits reject or
  last-wins; `JSONDecoder` silently picks one, and which one differs between implementations —
  a known header-smuggling vector). See D6.
- `JSONValue` enum for ad-hoc header parameters and claims.
- JSON string escaper used by thumbprint canonicalisation.
- `ECDSASignatureConverter`: DER ↔ P1363, both strip and left-pad paths, for P-256/384/521.
- `AlgorithmIdentifier`, `KeyID`, `MediaType` (typed wrappers, not bare `String`).

### jose-jwk
- Curves, typed EC/OKP/symmetric (and optionally RSA) keys; `JWK`, `PrivateJWK`, `JWKSet`.
- Thumbprints (RFC 7638), optionally thumbprint URIs (RFC 9278 — D11).
- `SignatureAlgorithm`, `Signer`, `Verifier`, `Signature<A>` and the built-in conformances.
- Secure Enclave (Apple only, `#if canImport(CryptoKit)` plus an OS check):

```swift
protocol P256SigningKey: Sendable {                   // the seam
    var x963PublicKey: Data { get }
    func derSignature(for digestInput: Data) throws -> Data
}
public struct SecureEnclaveSigner: Signer { typealias Algorithm = ES256 … }
```

  The production conformance wraps `SecureEnclave.P256.Signing.PrivateKey`; tests inject a
  software key through the same seam, so header construction, DER→P1363 conversion and error
  mapping run the production path. A software fallback is compiled only under
  `#if DEBUG && targetEnvironment(simulator)`. Key persistence in the keychain is D7.

### jose-jws
- `JWSHeader<Custom>`, `JWS<Custom>.Unverified` / `.Verified`, `VerificationKeys`.
- Serialisations: compact, flattened JSON, general JSON (multiple signatures); detached payload.
- RFC 7797 unencoded payload (`b64: false`) — D11.

### jose-jwe
- Key management: `dir`, `ECDH-ES`, `ECDH-ES+A128KW/A192KW/A256KW`, `A128KW/A192KW/A256KW`,
  `A128GCMKW/A192GCMKW/A256GCMKW`. Content encryption: `A128GCM/A192GCM/A256GCM`.
- Same shape as signing: `KeyManagementAlgorithm` and `ContentEncryptionAlgorithm` marker types,
  `Encrypter<Alg>` / `Decrypter<Alg>` protocols, `JWE.Encrypted` → `.decrypt(with:)` → `JWE.Decrypted`.
- Not CryptoKit-native, so gated on D5: `RSA-OAEP`, `RSA-OAEP-256`, `A*CBC-HS*`, `PBES2-*`.
- Never: `RSA1_5` (Bleichenbacher; deprecated by RFC 8725).
- `zip: DEF`: proposed as unsupported and rejected with a specific error (decompression bombs,
  compression side channels; RFC 8725 §3.6) — D11.

### jose-jwt
- `JWTClaims<Custom>`, claim builder, `JWTValidationPolicy`, `JWT<Custom>.Unverified/Verified/Validated`.
- Encrypted and nested (sign-then-encrypt) JWTs — D3.

### Out of scope unless you say otherwise
Remote JWKS fetching and caching (networking), X.509 chain validation for `x5c` (parameters are
carried and exposed, not validated), COSE/CBOR, `ES256K`, DPoP, SD-JWT.

## 4. Testing and interoperability

- Swift Testing throughout. Every guard gets a mutation check: I neuter it, confirm a test goes
  red, restore it, and report any guard for which no test failed.
- Each repo gets an `interop/` directory: `package.json` pinning `jose` (currently 6.2.12) with a
  lockfile, and a generator script that writes JSON fixtures into `Tests/…/Fixtures/`. Each
  fixture records the generator, the `jose` and Node versions, and "generated — do not hand-edit".
  Fixtures include negative cases with the rejection `jose` gives.
- Closed loop: a small Swift executable in each package emits tokens/thumbprints/JWKs as JSON; a
  Node script feeds them to `jose` and confirms acceptance, then confirms that tampered variants
  are refused. Run by `scripts/interop.sh` and in CI.
- RFC 7520 (JOSE cookbook) vectors are published as machine-readable JSON by the IETF working
  group; I'd vendor those files unmodified rather than transcribe anything from RFC text.
- DER↔P1363: sign several hundred real messages per curve and compare against the platform's own
  `rawRepresentation`, plus assertions that both the strip and pad paths were actually hit.
- CI matrix: macOS, Linux, Windows, Android (build-only where a test runner isn't practical — I
  will say which are build-only rather than calling them tested). Secure Enclave on real hardware
  cannot be verified by me or by CI; it will be reported as mock-tested only.

## 5. Decisions (settled 2026-10-04)

| #   | Decision | Outcome |
|-----|----------|---------|
| D1  | Minimum platforms | iOS 16, macOS 13, tvOS 16, watchOS 9, visionOS 1; swift-tools 6.0. No higher than the design needs. |
| D2  | Where `Signer`/`Verifier` live | **jose-core** (protocols, `Signature<A>`, algorithm marker types — no crypto). CryptoKit-backed conformances in jose-jwk. JWE's encrypter/decrypter protocols stay in jose-jwe. This supersedes the table in §1 and the jose-jwk list in §3. |
| D3  | How jwt reaches jwe | Second target in the jwt package for encrypted/nested JWTs. |
| D4  | Async | `sign` async, `verify` sync. |
| D5  | RSA, AES-CBC-HMAC, PBES2 | CryptoKit-native set first. **RSA (RS256/384/512, PS256/384/512) is required** and comes after jose-jws: built into `JOSEJWK`, backed by Security.framework on Apple and swift-crypto extras elsewhere; keys below 2048 bits are rejected. Other algorithms must remain addable inside the package or by a developer add-on without forking. |
| D6  | Duplicate JSON members | A small duplicate detector in core (not a full parser), applied to headers **and** claims; Foundation does the decoding. |
| D7  | Secure Enclave | Signer only; no keychain store. Mock-tested only. |
| D8  | JWE decryption errors | Cryptographic failures collapse to one error. Everything knowable without the key is reported precisely before any crypto runs. |
| D9  | Claim builder | Duplicates caught at runtime with a named error. |
| D10 | base64url trailing bits | Rejected. |
| D11 | Optional features | RFC 7797 yes, RFC 9278 yes, `zip: DEF` no. |
| D12 | Typed throws | Yes. |
| D13 | swift-crypto | Latest stable. |
| —   | Counterpart | panva/jose on Node. |
| —   | EdDSA | Both `Ed25519` (RFC 9864) and `EdDSA` (RFC 8037) are implemented as distinct algorithms. |
| —   | `typ`/`cty` comparison | Per RFC 7515 §4.1.9: case-insensitive, `application/` implied when the value has no `/`. |

### Later decisions

These were made after the packages were built. Where they conflict with anything above, they win.

| #   | Decision | Outcome |
|-----|----------|---------|
| D14 | Repository layout | One repository and one Swift package, with each module a separate library product (`JOSECore`, `JOSEJWK`, `JOSEJWS`, `JOSEJWE`, `JOSEJWT`, `JOSEJWTEncrypted`). The modules change together, and separate repositories meant ordered multi-repo merges and coordinated tags. The five original repositories' histories are merged into this one. |
| D15 | Async (supersedes D4) | `sign`, `verify`, `encryptKey` and `decryptKey` are all `async`, so that any key can live in hardware or behind a service, and so that no protocol has to become async later. |
| D16 | Secure Enclave (amends D7) | A keychain store, `SecureEnclaveKeyStore`, is included alongside the signer. |
| D17 | Naming | JWE key types are named for their role, `…Encrypter` and `…Decrypter`, symmetric and asymmetric alike. The common generic forms have `Simple…` typealiases (`SimpleJWS`, `SimpleJWE`, `SimpleJWT`, `SimpleEncryptedJWT`, `SimpleNestedJWT`). |
| D18 | Header key sources | `jku` and `x5c` are optional and overridable: each is used only when the caller supplies a provider or validator, through `HeaderKeyResolver`. |
| D19 | Name and license | The package is **JOSEKit**, MIT-licensed. Module names keep the `JOSE` prefix. |
| D20 | Parity with jose-swift | JOSEKit covers what beatt83/jose-swift does, except where listed here: RSA1_5, `zip`, PEM import, ES256K and secp256k1, and `x5c` validation on every platform are added. ECDH-1PU, C20P and XC20P (expired drafts) are not. Ed448 and X448 are not (jose-swift declares but does not implement them, and CryptoKit has neither). This supersedes D11's "`zip: DEF` no" and the earlier exclusion of RSA1_5. |
| D21 | RSA1_5 | Implemented with the countermeasures of RFC 7516 §11.5: a failed unwrap continues with a random key, so a padding failure and an authentication failure are the same `.decryptionFailed`. Used only when a caller builds an RSA1_5 encrypter or decrypter; nothing selects it otherwise. |
| D22 | Dependencies for parity | Each lives in its own product so that only applications using the feature build it: `swift-secp256k1` (ES256K, secp256k1 keys) in `JOSESecp256k1`; Apple's `swift-certificates` (cross-platform `x5c` validation) in `JOSEX509`. `zip` uses the system zlib on every platform (it ships with Apple's operating systems), producing raw DEFLATE (RFC 1951) as RFC 7516 §4.1.3 requires, with a limit on decompressed size (250 000 bytes by default, as panva/jose), and only from the protected header. Apple's Compression framework was the first choice there, but it silently discards input after the end of the stream, which zlib and the browsers' DecompressionStream refuse; one implementation keeps every platform the same. PEM import extends JOSEJWK's own DER reader and adds no dependency. |
| D23 | Test vectors | The JOSE cookbook (RFC 7520, RFC 7797, RFC 8037 examples) is vendored unmodified. Vectors that exist only as RFC text are not transcribed. |

## 6. Proposed order once approved

1. jose-core (base64url, JSON, DER↔P1363) with fixtures and mutation checks — stop for review.
2. jose-jwk — stop for review.
3. jose-jws — stop for review.
4. jose-jwt (signed) — stop for review.
5. jose-jwe, then encrypted/nested JWT — stop for review.

Nothing is committed at any step without your say-so.
