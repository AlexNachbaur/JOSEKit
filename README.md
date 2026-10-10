# jose-jwk

Keys for the JOSE packages: JSON Web Keys (RFC 7517), thumbprints (RFC 7638, RFC 9278), the
built-in signing and key-agreement algorithms, and the Secure Enclave.

Module: `JOSEJWK`. Depends on `jose-core`. Uses CryptoKit on Apple platforms and
[swift-crypto](https://github.com/apple/swift-crypto) elsewhere; RSA uses Security.framework on
Apple platforms and swift-crypto's extras elsewhere.

## Keys

| Type | Holds |
|---|---|
| `ECPublicKey<Curve>` / `ECPrivateKey<Curve>` | P-256, P-384, P-521 (`P256Curve`, `P384Curve`, `P521Curve`) |
| `Ed25519PublicKey` / `Ed25519PrivateKey` | Ed25519 signing keys |
| `X25519PublicKey` / `X25519PrivateKey` | X25519 key-agreement keys |
| `RSAPublicKey` / `RSAPrivateKey` | RSA, 2048 bits or more |
| `SymmetricKeyMaterial` | Shared secrets for HMAC and key wrapping |

Private and symmetric types are not `Codable` and print as redacted.

`JWK` holds public keys only; `PrivateJWK` and `SymmetricJWK` are separate types, so nothing that
takes a `JWK` (a `JWKSet`, a `jwk` header parameter) can be handed a secret. A key type this
package does not implement is kept as `JWK.Key.unrecognized` with its members intact.

```swift
let key = try JWK(json: data)                     // rejects duplicate members, private material, bad points
let thumbprint = try key.thumbprint()             // RFC 7638, SHA-256
let set = try JWKSet(json: data)                  // set.rejected says why any key was skipped
```

## Signing and verifying

`ECDSASigner<Curve>`, `Ed25519Signer<Algorithm>`, `RSASigner<Algorithm>` and `HMACSigner<Algorithm>`
conform to `Signer`; the matching verifiers conform to `Verifier`. A verifier built from a JWK
honours its `use`, `key_ops` and `alg`:

```swift
let verifier = try ECDSAVerifier<P256Curve>(jwk: key)       // ES256 by construction
let signer = try RSASigner<PS256>(privateKey: rsaKey)
```

Supported: ES256, ES384, ES512, Ed25519, EdDSA, HS256, HS384, HS512, RS256, RS384, RS512,
PS256, PS384, PS512.

## Secure Enclave (Apple platforms)

`SecureEnclaveSigner` signs ES256 with a key that never leaves the enclave:

```swift
let signer = try SecureEnclaveSigner.generate(accessibility: .afterFirstUnlockThisDeviceOnly)
let store = SecureEnclaveKeyStore(service: "com.example.keys")
try store.save(signer, as: "device", accessibility: .afterFirstUnlockThisDeviceOnly)
let restored = try store.load("device")
```

The accessibility is a required choice: `whenUnlocked…` fails in the background with
`errSecInteractionNotAllowed`. The store writes update-then-add, never delete-then-add. On the
simulator, debug builds use a software key behind the same API.

## Testing

```
swift test
./scripts/interop.sh     # closed-loop check against panva/jose and OpenSSL (needs Node)
```

Fixtures in `Tests/JOSEJWKTests/Fixtures` come from `interop/generate-fixtures.mjs`. Secure
Enclave and keychain tests run against real hardware only where the process is entitled to use
it; elsewhere they run against mocks and say so.
