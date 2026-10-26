# JOSESecp256k1

ES256K, ECDSA using secp256k1 and SHA-256, and secp256k1 keys in JWK form (RFC 8812).

Product: `JOSESecp256k1`. Depends on `JOSEJWS` and on
[swift-secp256k1](https://github.com/21-DOT-DEV/swift-secp256k1), which wraps bitcoin-core's
libsecp256k1. Built on Apple platforms, Linux and Android. On Windows the module is empty:
swift-secp256k1 adds its C sources to its targets with a build plugin that produces nothing
there. Xcode asks once to trust that plugin when the package is added.

## Keys

secp256k1 keys are `ECPublicKey<Secp256k1Curve>` and `ECPrivateKey<Secp256k1Curve>`, with the
same checks as the NIST curves: full-size coordinates, a point on the curve, and a private key
that matches its public key. In a JWK they are `JWK.Key.external` keys, read when parsing is
given `keyTypes: [.secp256k1]`:

```swift
import JOSEJWK
import JOSESecp256k1

let key = try ECPrivateKey<Secp256k1Curve>()
let jwk = PrivateJWK(.external(key), metadata: JWKMetadata(keyID: "k1"))
let json = try jwk.jsonRepresentation()

let read = try PrivateJWK(json: json, keyTypes: [.secp256k1])
let thumbprint = try read.publicJWK.thumbprint()
```

## Signing and verifying

`ECDSASigner` and `ECDSAVerifier` from JOSEJWK sign and verify ES256K on `Secp256k1Curve`, and
`ES256K` can be listed wherever an algorithm is accepted:

```swift
let signer = try ECDSASigner(privateKey: key, keyID: "k1")       // ES256K by construction
let token = try await SimpleJWS.Signed(signing: payload, with: signer).compactSerialization()

let keys = VerificationKeys(jwks: set, allowing: [.es256k])
```

A secp256k1 key in a JWK Set parsed without `keyTypes` is `JWK.Key.unrecognized`, and still
verifies: the verifier reads the EC members itself, with the same checks.

Signatures always have a low S (BIP 62), because libsecp256k1 produces nothing else. Verification
accepts either form, because RFC 8812 does not require low S and other signers, OpenSSL among
them, produce a high S half the time. A high S is replaced by `n − s` before libsecp256k1, which
accepts only low S, checks it.

ES256K is for signatures only. ECDH-ES on secp256k1 is not provided.

## Testing

```
swift test --filter JOSESecp256k1Tests
./scripts/interop.sh secp256k1     # closed-loop check against OpenSSL (needs Node)
```

panva/jose 6 has no ES256K, because WebCrypto has no secp256k1. The fixtures in
`Tests/JOSESecp256k1Tests/Fixtures` therefore come from OpenSSL, through Node's crypto module, by
`interop/secp256k1/generate-fixtures.mjs`; jose supplies the thumbprints. They include signatures
in both S forms, and OpenSSL's verdicts on malformed ones.
