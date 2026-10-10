# jose-jwt

JSON Web Token (RFC 7519): claims, a claims builder, validation, and the signed, encrypted and
nested forms.

Products: `JOSEJWT` (signed JWTs; depends on `jose-jws`) and `JOSEJWTEncrypted` (encrypted and
nested JWTs; adds `jose-jwe`). An application that only signs and verifies does not build the
encryption code.

## Three states, three names for the claims

```swift
let validated = try SignedJWT<MyClaims>.Unverified(compact: token)
    .verify(with: keys)            // → Verified: signature good, claims untrusted
    .validate(policy)              // → Validated: claims checked
```

Claims are `unverifiedClaims()` before the signature check, `unvalidatedClaims` after it, and
`claims` only on `Validated`. Code that acts on a token should take a `Validated`, which cannot
be made any other way.

## Building a token

```swift
let token = try await SignedJWT<EmptyClaims>.sign(with: signer, type: "at+jwt") {
    Issuer("https://issuer.example")
    Subject(userID)
    Audience("https://api.example")
    ExpiresIn(.minutes(5))
    IssuedAt()
    JWTID.random()
    Claim("scope", "read write")
}
```

Typed claims go in a `Codable` struct as the `Custom` parameter; registered claims cannot be
written by it or by `Claim(...)`. Setting a claim twice is an error naming the claim.

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
refused unless `requiresExpiration: false`.

## Encrypted and nested JWTs (`JOSEJWTEncrypted`)

```swift
let token = try EncryptedJWT<MyClaims, EmptyHeaderParameters>.encrypt(claims, to: recipient, using: A256GCM.self)
let validated = try await EncryptedJWT<MyClaims, EmptyHeaderParameters>.Encrypted(compact: token)
    .decrypt(with: keys)
    .validate(policy)
```

A token encrypted to a public key proves nothing about who wrote it. For an issuer, nest:

```swift
let token = try await NestedJWT<MyClaims, EmptyHeaderParameters>
    .signThenEncrypt(claims, signedBy: signer, encryptedTo: recipient, using: A256GCM.self)
let validated = try await NestedJWT<MyClaims, EmptyHeaderParameters>.decrypt(token, with: keys)
    .verify(with: verificationKeys)      // the inner token is an ordinary Unverified JWT
    .validate(policy)
```

## Testing

```
swift test
./scripts/interop.sh     # closed-loop checks against panva/jose (needs Node)
```
