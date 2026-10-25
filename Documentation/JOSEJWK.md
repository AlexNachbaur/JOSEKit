# JOSEJWK

Keys for the JOSE modules: JSON Web Keys (RFC 7517), thumbprints (RFC 7638, RFC 9278), the
built-in signing and key-agreement algorithms, and the Secure Enclave.

Product: `JOSEJWK`. Depends on `JOSECore`. Uses CryptoKit on Apple platforms and
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

### Key types from other modules

A module can add a key type without a fork. Its keys conform to `ExternalPublicKey` and
`ExternalPrivateKey`, and are carried as `JWK.Key.external` and `PrivateJWK.Key.external`. Two
external keys are equal when their `kty` and JWK members are. For an elliptic curve, conforming
the curve to `ExternalCurve` is enough: `ECPublicKey` and `ECPrivateKey` on it become external
keys, and `ECKeyType<Curve>` reads them. `JOSESecp256k1` adds secp256k1 this way.

Parsing reads an external key only when it is told about its type:

```swift
let key = try JWK(json: data, keyTypes: [.secp256k1])       // JWK.Key.external
let set = try JWKSet(json: data, keyTypes: [.secp256k1])
let unread = try JWK(json: data)                            // JWK.Key.unrecognized
```

`ECDSAVerifier` reads a key on its own curve from either, so a key set parsed without
`keyTypes`, such as one fetched by `VerificationKeys(jwksAt:)`, still verifies.

### PEM

`JWK(pem:)` and `PrivateJWK(pem:)` read one PEM block (RFC 7468), with optional `metadata`:

| Type | PEM label | Keys |
|---|---|---|
| `JWK` | `PUBLIC KEY` (SubjectPublicKeyInfo) | RSA, P-256, P-384, P-521, Ed25519, X25519 |
| `JWK` | `RSA PUBLIC KEY` (PKCS#1) | RSA |
| `PrivateJWK` | `PRIVATE KEY` (PKCS#8, versions 1 and 2) | RSA, P-256, P-384, P-521, Ed25519, X25519 |
| `PrivateJWK` | `RSA PRIVATE KEY` (PKCS#1) | RSA |
| `PrivateJWK` | `EC PRIVATE KEY` (SEC1) | P-256, P-384, P-521 |

```swift
let key = try JWK(pem: pemText, metadata: JWKMetadata(keyID: "signing-2026"))
```

Reading is strict:

- The DER must be canonical.
- A public key carried inside a private key must be that key's own.
- Encrypted keys (`ENCRYPTED PRIVATE KEY`, or OpenSSL's legacy `Proc-Type` headers) are refused, and so are certificates.
- Any other algorithm or curve, such as brainpool or Ed448, fails with `unsupportedKeyAlgorithm(oid:)`.
- The usual key checks apply, for example RSA keys must be at least 2048 bits.

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
swift test --filter JOSEJWKTests
./scripts/interop.sh jwk     # closed-loop check against panva/jose and OpenSSL (needs Node)
```

Fixtures in `Tests/JOSEJWKTests/Fixtures` come from `interop/jwk/generate-fixtures.mjs`, and
`pem.json` from `interop/jwk/generate-pem-fixtures.mjs` (OpenSSL's PEM output for each key, with
the same key as a JWK). Secure
Enclave and keychain tests run against real hardware only where the process is entitled to use
it; elsewhere they run against mocks and say so.
