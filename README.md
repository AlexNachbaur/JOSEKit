# jose-jwe

JSON Web Encryption (RFC 7516): encryption and decryption in the compact, flattened JSON and
general JSON serializations, with multiple recipients and additional authenticated data.

Module: `JOSEJWE`. Depends on `jose-core` and `jose-jwk`. AES-CBC and PBKDF2 use CommonCrypto on
Apple platforms and swift-crypto's extras elsewhere.

## Algorithms

Key management (`alg`): `dir`, `A128KW`/`A192KW`/`A256KW`, `A128GCMKW`/`A192GCMKW`/`A256GCMKW`,
`ECDH-ES` and `ECDH-ES+A128KW`/`A192KW`/`A256KW` (P-256, P-384, P-521, X25519), `RSA-OAEP`,
`RSA-OAEP-256`, `PBES2-HS256+A128KW`/`HS384+A192KW`/`HS512+A256KW`.

Content encryption (`enc`): `A128GCM`/`A192GCM`/`A256GCM`, `A128CBC-HS256`/`A192CBC-HS384`/`A256CBC-HS512`.

Not implemented, on purpose: `RSA1_5` and `zip`.

## Encrypting

```swift
let recipient = try RSAOAEPEncrypter<RSAOAEP256>(jwk: theirPublicKey)   // honours use, key_ops, alg
let sealed = try JWE<EmptyHeaderParameters>.encrypt(plaintext, to: recipient, using: A256GCM.self)
try sealed.compactSerialization()
```

`alg` comes from the recipient's type and `enc` from the content encryption type. Several
recipients, each able to decrypt on their own, go in the general serialization:

```swift
let sealed = try JWE<EmptyHeaderParameters>.encrypt(
    plaintext,
    to: [AnyKeyEncrypter(rsaRecipient), AnyKeyEncrypter(ecdhRecipient)],
    using: A256GCM.self,
    header: JWEHeaderParameters()
)
```

## Decrypting

```swift
let keys = DecryptionKeys([AnyKeyDecrypter(try RSAOAEPDecrypter<RSAOAEP256>(privateKey: mine))])
let decrypted = try await JWE<EmptyHeaderParameters>.Encrypted(compact: token).decrypt(with: keys)
decrypted.plaintext
```

`DecryptionKeys` is also the list of acceptable key management algorithms. Every cryptographic
failure is the single error `.decryptionFailed`; a failed key unwrap continues with a random key
so that it is indistinguishable from a failed authentication tag (RFC 7516 §11.5). Everything
knowable without a key, such as a missing `epk` or an unsupported `enc`, is reported precisely.

PBES2 bounds the iteration count a token may demand (`maximumIterationCount`, default 10 000),
since the token chooses it and so the work you do.

## Extending

`KeyManagementAlgorithm`, `KeyEncrypter`, `KeyDecrypter` and `ContentEncryptionAlgorithm` are
public protocols. An add-on needs no fork and no registration.

## Testing

```
swift test
./scripts/interop.sh     # closed-loop check against panva/jose (needs Node)
```

Fixtures come from `interop/generate-fixtures.mjs`.
