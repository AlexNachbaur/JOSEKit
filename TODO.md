# Deferred and skipped work

Things JOSEKit deliberately does not do yet, or has chosen not to do, and why. The reasoning
behind each lives in [DESIGN.md](DESIGN.md) under the decision named. When one of these is
picked up, remove it here in the same change.

## Deferred

These may be done later.

- **`zip` (`DEF`) on Windows.** Windows has no system zlib, so `JWECompression.deflate` does
  not exist there. A received compressed JWE is refused with `unsupportedCompression`. Bundling
  zlib's source would fix this, at the cost of keeping a copy of zlib up to date. (D22)
- **Revocation checking for `x5c`.** The planned cross-platform certificate chain validator
  (on swift-certificates, in `JOSEX509`) will check the chain and its validity dates, not OCSP
  or CRLs. Revocation needs network fetches and policy choices of its own. (D18, D22)
- **Encrypted PEM keys.** `ENCRYPTED PRIVATE KEY` (PKCS#8 with PBES2) and OpenSSL's legacy
  `Proc-Type: 4,ENCRYPTED` keys are refused. Callers decrypt them first.
- **Flattening the grouping types.** `JWE`, `JWS`, `JWT`, `EncryptedJWT` and `NestedJWT` hold
  only nested types (`JWE.Encrypted`, `JWS.Signed`, ...). They could become top-level generic
  types. (D24)
- **First release.** `0.1.0` is tagged once the parity work is finished. Until then the API may
  change without notice.

## Not planned

These have been considered and set aside.

- **ECDH-1PU, `C20P` and `XC20P`.** Their specifications are expired drafts. (D20)
- **Ed448 and X448.** CryptoKit and swift-crypto implement neither. (D20)
- **ECDH-ES on secp256k1.** RFC 8812 registers secp256k1 for ES256K signatures only.
- **Vectors that exist only as RFC text.** Only the machine-readable JOSE cookbook is vendored;
  vectors are not transcribed from RFC prose. (D23)
