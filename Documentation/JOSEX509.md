# JOSEX509

Validation of the X.509 certificate chains a JWS carries in `x5c` (RFC 7515 §4.1.6), on every
platform.

Product: `JOSEX509`. Depends on `JOSEJWS` and on Apple's
[swift-certificates](https://github.com/apple/swift-certificates).

## Validating `x5c`

`X509CertificateChainValidator` is a `CertificateChainValidator` for `HeaderKeyResolver`. It
validates the chain against the CA certificates you give it, and returns the signing
certificate's public key:

```swift
import JOSEJWS
import JOSEX509

let resolver = HeaderKeyResolver(
    algorithms: [.es256, .rs256],
    certificateChainValidator: try X509CertificateChainValidator(anchors: [issuerCADER])
)
let verified = try await SimpleJWS.Unverified(compact: token).verify(resolving: resolver)
```

The anchors are the whole story: a chain is accepted only if it ends at one of them. No system
root store is consulted, because a certificate from any public CA is not evidence that the
expected issuer signed the token.

It checks, by RFC 5280 path validation:

- the signature on each certificate,
- validity periods, at the current time or at a `clock` you inject,
- basic constraints and path length,
- name constraints,
- that no certificate has a critical extension that nothing understands,
- key usage, wherever the extension is present: an issuer's must allow certificate signing, and
  the signing certificate's must allow digital signatures.

swift-certificates deliberately does not check key usage, so JOSEX509 adds that check. The
signing-certificate half is stricter than OpenSSL's default.

It does not check revocation (OCSP or CRLs); see [TODO.md](../TODO.md). It does not fetch a
missing intermediate: the chain in `x5c` has to stand on its own.

The signing certificate's key is returned for RSA, P-256, P-384, P-521 and Ed25519 keys.
swift-certificates cannot read a certificate whose key is on another curve, such as secp256k1,
and the chain is refused.

## On Apple platforms

`SecTrustCertificateChainValidator` in JOSEJWS does the same job with Security.framework, under
the same rules for anchors and fetching. The two differ on some chains:

| Chain | `X509CertificateChainValidator` | `SecTrustCertificateChainValidator` |
|---|---|---|
| Ed25519 signing key | key returned | refused: `SecKey` has no Ed25519 |
| Signing certificate's key usage without `digitalSignature` | refused | accepted |

## Testing

```
swift test --filter JOSEX509Tests
```

`Tests/JOSEX509Tests/Fixtures/chains.json` comes from `interop/x509/generate-fixtures.mjs`. It
builds a small PKI with OpenSSL, assembles certificate chains from it, and records
`openssl verify`'s verdict on each. The chains include:

- valid chains, with and without an intermediate
- an untrusted root and a missing intermediate
- expired and not-yet-valid certificates
- an issuer that is not a CA, or may not sign certificates
- an exceeded path length
- an altered signature
- unknown and malformed critical extensions

Both validators are tested against those verdicts, with each difference documented.
