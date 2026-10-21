# JOSEKit

JSON Object Signing and Encryption in Swift: JSON Web Keys, Signatures, Encryption and Tokens
(RFC 7515–7519 and their companions), built so that misuse fails to compile where it can and
fails loudly where it cannot.

- **Algorithms are types.** An ES256 key cannot verify an ES384 signature, `alg: none` has no
  type, and the keys you pass in are also the list of algorithms you accept.
- **Trust is a type-state.** A parsed token is `Unverified`; its payload or claims are reachable
  only after verification, and a JWT's claims only after validation against a policy that names
  its issuer, audience and type.
- **Strict parsing.** Duplicate JSON members, padded or non-canonical base64url, unknown critical
  headers and malformed keys are refused with an error naming the problem.
- **Uniform decryption failure.** Every cryptographic JWE failure is the same error, so it cannot
  become an oracle; everything knowable without a key is reported precisely.
- **Extensible.** Algorithms, keys, header and claim types are protocols. A Secure Enclave key, a
  remote key service or an algorithm this package does not ship can conform without a fork.

Swift 6 with strict concurrency and typed throws. Apple platforms (macOS 13, iOS 16, tvOS 16,
watchOS 9, visionOS 1), Linux, Windows and Android. CryptoKit on Apple platforms and
[swift-crypto](https://github.com/apple/swift-crypto) elsewhere. JWE compression uses the system
zlib, so it is not available on Windows.

## Installation

```swift
dependencies: [
    .package(url: "https://github.com/AlexNachbaur/JOSEKit.git", from: "0.1.0"),
],
targets: [
    .target(
        name: "MyApp",
        dependencies: [.product(name: "JOSEJWT", package: "JOSEKit")]
    ),
]
```

## Modules

Each module is its own library product, so an application builds only what it uses.

| Product | What it does | Depends on | Documentation |
|---|---|---|---|
| `JOSECore` | base64url, strict JSON, signing protocols, algorithm types. No cryptography. | nothing | [JOSECore](Documentation/JOSECore.md) |
| `JOSEJWK` | Keys, JWK and JWK Sets, PEM import, thumbprints, the built-in algorithms, Secure Enclave. | `JOSECore` | [JOSEJWK](Documentation/JOSEJWK.md) |
| `JOSEJWS` | JSON Web Signature in all three serializations, key resolution from headers. | `JOSEJWK` | [JOSEJWS](Documentation/JOSEJWS.md) |
| `JOSEJWE` | JSON Web Encryption in all three serializations, several recipients. | `JOSEJWK` | [JOSEJWE](Documentation/JOSEJWE.md) |
| `JOSEJWT` | Signed JWTs: claims, a claims builder, validation policies. | `JOSEJWS` | [JOSEJWT](Documentation/JOSEJWT.md) |
| `JOSEJWTEncrypted` | Encrypted and nested JWTs. | `JOSEJWT`, `JOSEJWE` | [JOSEJWT](Documentation/JOSEJWT.md) |

## A signed JWT, end to end

```swift
import JOSEJWK
import JOSEJWS
import JOSEJWT

let token = try await SimpleJWT.Signed(signingWith: signer, type: "at+jwt") {
    Issuer("https://issuer.example")
    Audience("https://api.example")
    ExpiresIn(.seconds(300))
}.compactSerialization()

let provider = CachingJWKSetProvider(URLSessionJWKSetProvider())
let keys = try await VerificationKeys(jwksAt: issuerJWKSURL, provider: provider, allowing: [ES256.self])
let validated = try await SimpleJWT.Unverified(compact: token)
    .verify(with: keys)
    .validate(JWTValidationPolicy(
        issuer: .exactly("https://issuer.example"),
        audience: .contains("https://api.example"),
        type: .exactly("at+jwt")
    ))
```

## Testing

```
swift test               # every module
./scripts/interop.sh     # closed-loop checks against panva/jose (needs Node 22)
```

Test fixtures are generated from [panva/jose](https://github.com/panva/jose) (and OpenSSL for
certificates) by the scripts in `interop/`, and are not edited by hand. The closed-loop checks
have the Node implementation judge tokens, keys and signatures this package produces, and
compare this package's verdicts with its own on tokens it produces. `./scripts/interop.sh jws jwe` checks only the modules
named.

[DESIGN.md](DESIGN.md) records the design and the decisions behind it.
