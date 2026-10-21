# JOSEJWE

JSON Web Encryption (RFC 7516): encryption and decryption in the compact, flattened JSON and
general JSON serializations, with multiple recipients and additional authenticated data.

Product: `JOSEJWE`. Depends on `JOSECore` and `JOSEJWK`. AES-CBC and PBKDF2 use CommonCrypto on
Apple platforms and swift-crypto's extras elsewhere.

## Algorithms

Key management (`alg`): `dir`, `A128KW`/`A192KW`/`A256KW`, `A128GCMKW`/`A192GCMKW`/`A256GCMKW`,
`ECDH-ES` and `ECDH-ES+A128KW`/`A192KW`/`A256KW` (P-256, P-384, P-521, X25519), `RSA-OAEP`,
`RSA-OAEP-256`, `RSA1_5`, `PBES2-HS256+A128KW`/`HS384+A192KW`/`HS512+A256KW`.

Content encryption (`enc`): `A128GCM`/`A192GCM`/`A256GCM`, `A128CBC-HS256`/`A192CBC-HS384`/`A256CBC-HS512`.
They are the cases of `ContentEncryption`, each delegating to its type (`A256GCM` and so on).
Pass one as `using: .a256gcm`. Decryption accepts `ContentEncryption.allCases` unless given a
shorter list. An algorithm this package does not ship is a type conforming to
`ContentEncryptionAlgorithm`, passed as an instance in the same places.

`RSA1_5` is there for systems that still send it. Its decryption leaks whether the padding was
valid unless every failure looks the same, so any failure to recover the key continues with a
random key and ends in the same `.decryptionFailed` as any other failure (RFC 7516 §11.5). It is
used only when you build an `RSAEncrypter<RSA15>` or `RSADecrypter<RSA15>`, or list `.rsa15` in
`DecryptionKeys(jwks:allowing:)`. Prefer `RSA-OAEP-256`.

Compression (`zip`): `DEF`, raw DEFLATE, using the system zlib. Not available on Windows.

## Compression

```swift
let sealed = try await SimpleJWE.Encrypted(
    encrypting: plaintext,
    to: recipient,
    using: .a256gcm,
    header: JWEHeaderParameters(compression: .deflate)
)
let decrypted = try await jwe.decrypt(with: keys, maximumDecompressedByteCount: 100_000)
```

`zip` is always written to, and only accepted from, the protected header (RFC 7516 §4.1.3).
Decryption refuses a plaintext that decompresses to more than `maximumDecompressedByteCount`
bytes (250 000 by default, as panva/jose), stopping as soon as the limit is passed, so a small
token cannot expand without bound. A limit of 0 refuses compressed JWEs before any cryptography
is done. Compressing secrets together with text an attacker chooses can reveal the secrets
through the ciphertext's length, so leave compression off unless the plaintext is all yours.

`JWECompression` has a case only for each compression this platform supports. Windows has no
system zlib, so `JWECompression.deflate` does not exist there, and code that asks for compression
fails to build rather than at runtime. A received JWE with `"zip": "DEF"` is refused there with
`unsupportedCompression(algorithm: "DEF")`. On Linux, building needs zlib's headers (`zlib1g-dev`
on Debian and Ubuntu, `zlib-devel` on Fedora and RHEL).

## Encrypting

```swift
let recipient = try RSAEncrypter<RSAOAEP256>(jwk: theirPublicKey)   // honours use, key_ops, alg
let sealed = try await SimpleJWE.Encrypted(encrypting: plaintext, to: recipient, using: .a256gcm)
try sealed.compactSerialization()
```

`SimpleJWE` is `JWE<EmptyHeaderParameters>`. `alg` comes from the recipient's type and `enc`
from the content encryption. Several recipients, each able to decrypt on their own, go in
the general serialization; each recipient's key ID goes in its own header:

```swift
let sealed = try await SimpleJWE.Encrypted(
    encrypting: plaintext,
    to: [AnyKeyEncrypter(rsaRecipient), AnyKeyEncrypter(ecdhRecipient)],
    using: .a256gcm,
    header: JWEHeaderParameters()
)
```

`dir` and `ECDH-ES` supply the content key themselves, so they refuse to share a JWE with any
other recipient, in any position.

## Keys

Every algorithm has an encrypter and a decrypter type, named for the role:

| `alg` | Encrypter | Decrypter |
|---|---|---|
| `dir` | `DirectEncrypter` | `DirectDecrypter` |
| `A…KW` | `AESKeyWrapEncrypter<A256KW>` | `AESKeyWrapDecrypter<A256KW>` |
| `A…GCMKW` | `AESGCMKeyWrapEncrypter<A256GCMKW>` | `AESGCMKeyWrapDecrypter<A256GCMKW>` |
| `PBES2-…` | `PBES2Encrypter<PBES2HS256A128KW>` | `PBES2Decrypter<PBES2HS256A128KW>` |
| `ECDH-ES…` | `ECDHESEncrypter<ECDHESA256KW>` | `ECDHESDecrypter<ECDHESA256KW, ECPrivateKey<P256Curve>>` |
| `RSA-OAEP…`, `RSA1_5` | `RSAEncrypter<RSAOAEP256>` | `RSADecrypter<RSAOAEP256>` |

All but PBES2 can be built from a JWK with `init(jwk:)`, which honours its `use`, `key_ops` and
`alg`. Private JWKs for the asymmetric algorithms can also be turned into a set of keys at once:

```swift
let keys = DecryptionKeys(jwks: myPrivateKeys, allowing: [.ecdhESA256KW, .rsaOAEP256])
```

The algorithms that can be listed are the cases of `KeyManagement`, each delegating to its type
(`ECDHESA256KW` and so on). An algorithm added outside this package conforms to
`JWKDecryptableAlgorithm` and is listed as an instance.

## Decrypting

```swift
let keys = DecryptionKeys {
    try RSADecrypter<RSAOAEP256>(privateKey: mine)
    try AESKeyWrapDecrypter<A256KW>(jwk: sharedKey)
}
let decrypted = try await SimpleJWE.Encrypted(compact: token).decrypt(with: keys)
decrypted.plaintext
```

`DecryptionKeys` is also the list of acceptable key management algorithms. Every cryptographic
failure is the single error `.decryptionFailed`; a failed key unwrap continues with a random key
so that it is indistinguishable from a failed authentication tag (RFC 7516 §11.5). Everything
knowable without a key, such as a missing `epk` or an unsupported `enc`, is reported precisely,
whichever order the keys are in.

`PBES2Decrypter` bounds the iteration count a token may demand (`maximumIterationCount`, default
10 000), since the token chooses it and so the work you do.

Encryption and decryption are both `async`, so that a key held by a remote service or in
hardware can conform to `KeyEncrypter` or `KeyDecrypter`.

## Extending

`KeyManagementAlgorithm`, `KeyEncrypter`, `KeyDecrypter` and `ContentEncryptionAlgorithm` are
public protocols. An add-on needs no fork and no registration.

## Testing

```
swift test --filter JOSEJWETests
./scripts/interop.sh jwe     # closed-loop check against panva/jose (needs Node)
```

Fixtures come from `interop/jwe/generate-fixtures.mjs`.
