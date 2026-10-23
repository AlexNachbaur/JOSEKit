# JOSEJWT and JOSEJWTEncrypted

JSON Web Token (RFC 7519): claims, a claims builder, validation, and the signed, encrypted and
nested forms.

Products: `JOSEJWT` (signed JWTs; depends on `JOSEJWS`) and `JOSEJWTEncrypted` (encrypted and
nested JWTs; adds `JOSEJWE`). An application that only signs and verifies does not build the
encryption code.

## Three states, three names for the claims

```swift
let validated = try await SignedJWT<MyClaims>.Unverified(compact: token)
    .verify(with: keys)            // → Verified: signature good, claims untrusted
    .validate(policy)              // → Validated: claims checked
```

Claims are `unverifiedClaims()` before the signature check, `unvalidatedClaims` after it, and
`claims` only on `Validated`; `rawClaims` holds every claim as received. Code that acts on a
token should take a `Validated`, which cannot be made any other way.

`SignedJWT<MyClaims>` is `JWT<MyClaims, EmptyHeaderParameters>`, and `SimpleJWT` is
`JWT<EmptyClaims, EmptyHeaderParameters>`. Verification is `async`, as signing is.

## Building a token

```swift
let signed = try await SimpleJWT.Signed(signingWith: signer, type: "at+jwt") {
    Issuer("https://issuer.example")
    Subject(userID)
    Audience("https://api.example")
    ExpiresIn(.seconds(300))
    IssuedAt()
    JWTID.random()
    Claim("scope", "read write")
}
let token = signed.compactSerialization()
```

Typed claims go in a `Codable` struct as the `Custom` parameter, and are written exactly as the
type encodes them. Registered claims cannot be written by it or by `Claim(...)`. Setting a claim
twice is an error naming the claim. Your own components conform to `JWTClaimComponent` and set
fields on the `JWTClaimsDraft` they are given, calling `claim(_:)` for each claim they set.

## Validation has no defaults

```swift
let policy = JWTValidationPolicy(
    issuer: .exactly("https://issuer.example"),
    audience: .contains("https://api.example"),
    type: .exactly("at+jwt"),            // compared as a media type
    leeway: .seconds(30),
    clock: .system                       // injectable
)
```

Issuer, audience and type must be stated or written as `.unchecked`. Tokens without `exp` are
refused unless `requiresExpiration: false`. A negative leeway counts as zero.

## Encrypted and nested JWTs (`JOSEJWTEncrypted`)

```swift
let token = try await EncryptedJWT<MyClaims, EmptyHeaderParameters>
    .Encrypted(encrypting: claims, to: recipient, using: .a256gcm)
    .compactSerialization()
let validated = try await EncryptedJWT<MyClaims, EmptyHeaderParameters>.Encrypted(compact: token)
    .decrypt(with: keys)
    .validate(policy)
```

A token encrypted to a public key proves nothing about who wrote it. For an issuer, nest:

```swift
let token = try await NestedJWT<MyClaims, EmptyHeaderParameters>
    .Encrypted(signing: claims, signedBy: signer, encryptedTo: recipient, using: .a256gcm)
    .compactSerialization()
let encrypted = try NestedJWT<MyClaims, EmptyHeaderParameters>.Encrypted(compact: token)
encrypted.header                         // the outer header, readable before decryption
let validated = try await encrypted
    .decrypt(with: keys)                 // → Decrypted: outer header and the unverified inner JWT
    .verify(with: verificationKeys)      // → the inner JWT's Verified
    .validate(policy)
```

Any `iss`, `sub` or `aud` that an encrypted token's header repeats (RFC 7519 §5.3) must equal the
claim. For a nested token that is checked against the signed claims, after verification.
`SimpleEncryptedJWT` and `SimpleNestedJWT` are the forms with registered claims and header
parameters only.

## Testing

```
swift test --filter "JOSEJWTTests|JOSEJWTEncryptedTests"
./scripts/interop.sh jwt     # closed-loop checks against panva/jose (needs Node)
```

Fixtures come from `interop/jwt/generate-fixtures.mjs` and
`interop/jwt/generate-encrypted-fixtures.mjs`.
