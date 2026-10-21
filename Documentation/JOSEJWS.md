# JOSEJWS

JSON Web Signature (RFC 7515): signing and verification in the compact, flattened JSON and
general JSON serializations, with detached and unencoded (RFC 7797) payloads.

Product: `JOSEJWS`. Depends on `JOSECore` and `JOSEJWK`.

## Verification is a type-state

```swift
let unverified = try SimpleJWS.Unverified(compact: token)
unverified.header                    // readable, for choosing a key; not yet trustworthy
let verified = try await unverified.verify(with: keys)
verified.payload                     // exists only here
```

`SimpleJWS` is `JWS<EmptyHeaderParameters>`, for headers with registered parameters only. The
payload before verification is reachable only as `unverifiedPayload`. The signature is checked
over the bytes received, never over a re-encoded header.

Verification is `async`, like signing, so that a key held by a remote service or in hardware can
conform to `Verifier`.

## Keys and algorithms

`VerificationKeys` is also the algorithm allow-list: a signature is only tried against verifiers
for the `alg` it names, so there is no separate list to forget. Build it from verifiers, with a
result builder, or from a JWK Set:

```swift
let keys = VerificationKeys(jwks: set, allowing: [ES256.self, PS256.self])
let keys = try VerificationKeys {
    try ECDSAVerifier(publicKey: p256, keyID: "a")
    try HMACVerifier<HS256>(key: secret)
}
```

For a JWK Set at a URL you know in advance, such as an OpenID Connect issuer's `jwks_uri`:

```swift
let provider = CachingJWKSetProvider(URLSessionJWKSetProvider())
let keys = try await VerificationKeys(jwksAt: issuerJWKSURL, provider: provider, allowing: [RS256.self, ES256.self])
```

`alg: none` has no type and cannot be constructed. A token naming a `kid` is tried only against
keys with that ID or with none.

## Signing

```swift
let signed = try await SimpleJWS.Signed(signing: payload, with: signer, header: JWSHeaderParameters(type: "JWT"))
try signed.compactSerialization()
try signed.flattenedJSONSerialization(detached: true)
try await signed.adding(signatureWith: other, header: JWSHeaderParameters()).generalJSONSerialization()
```

`alg` comes from the signer's type. A custom header type (conforming to `HeaderParameters`)
cannot encode `alg`, `crit`, `b64` or any registered parameter; the extensions it declares as
critical are listed in `crit` automatically, and a reader that does not declare them refuses the
token.

## Keys from the header (optional)

`HeaderKeyResolver` turns `jku`, `x5c` and `jwk` into verification keys. Every source is opt-in
and bounded:

```swift
let resolver = HeaderKeyResolver(
    algorithms: [ES256.self],
    jwkSetProvider: CachingJWKSetProvider(URLSessionJWKSetProvider()),
    allowedJWKSetURLs: [issuerJWKSURL],                         // exact HTTPS URLs only
    certificateChainValidator: try SecTrustCertificateChainValidator(anchors: [issuerCA])
)
let verified = try await unverified.verify(resolving: resolver)
```

With several signatures, each is checked against the keys its own header names.

`JWKSetProvider` and `CertificateChainValidator` are protocols; supply your own to change the
transport, the caching or the trust rules. `URLSessionJWKSetProvider` uses a body only when it
comes from the URL requested; on Apple platforms it also refuses redirects and stops reading at
`maximumByteCount`. `SecTrustCertificateChainValidator` exists on Apple platforms, trusts only
the anchors it is given and does not fetch anything from the network. An embedded `jwk` is used
only when `allowsEmbeddedKey` is on.

## Testing

```
swift test --filter JOSEJWSTests
./scripts/interop.sh jws     # closed-loop check against panva/jose (needs Node)
```

Fixtures come from `interop/jws/generate-fixtures.mjs` (jose) and
`interop/jws/generate-certificates.mjs` (OpenSSL).
