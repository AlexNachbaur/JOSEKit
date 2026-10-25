// Answers a challenge from `interop/secp256k1/closed-loop.mjs` so that the counterpart can check
// ES256K JWSs and secp256k1 JWKs produced by JOSESecp256k1, and can check this package's verdicts
// on JWSs the counterpart made. Reads the challenge as JSON on stdin and writes the response as
// JSON on stdout. Not part of the library; see `scripts/interop.sh`.
//
// Empty where JOSESecp256k1 is (Windows).

#if canImport(P256K)
    import Foundation
    import JOSECore
    import JOSEJWK
    import JOSEJWS
    import JOSESecp256k1

    struct Challenge: Decodable {
        struct VerifyCase: Decodable {
            let jwk: String
            let token: String
        }

        /// Hex-encoded payload to sign.
        let payload: String
        /// Private JWKs made by the counterpart, to sign with.
        let signingKeys: [String]
        /// JWSs made by the counterpart, some valid and some not, for this package to judge.
        let verify: [VerifyCase]
    }

    struct Response: Encodable {
        struct Generated: Encodable {
            let keyID: String
            let privateJwk: String
            let publicJwk: String
            let thumbprint: String
            let token: String
        }
        struct Verdict: Encodable {
            let accepted: Bool
            let payload: String?
        }

        var signed: [String] = []
        var generated: [Generated] = []
        var verdicts: [Verdict] = []
    }

    struct InteropError: Error, CustomStringConvertible {
        let description: String
    }

    func bytes(fromHex hex: String) throws -> Data {
        let digits = Array(hex.utf8)
        guard digits.count.isMultiple(of: 2) else {
            throw InteropError(description: "hex string has odd length \(digits.count)")
        }
        var output = Data(capacity: digits.count / 2)
        for index in stride(from: 0, to: digits.count, by: 2) {
            guard let byte = UInt8(String(decoding: digits[index..<(index + 2)], as: UTF8.self), radix: 16) else {
                throw InteropError(description: "invalid hex at offset \(index)")
            }
            output.append(byte)
        }
        return output
    }

    func hex(_ data: Data) -> String {
        data.map { byte in
            let digits = String(byte, radix: 16)
            if digits.count == 1 {
                return "0" + digits
            }
            return digits
        }
        .joined()
    }

    func text(_ data: Data) -> String {
        String(decoding: data, as: UTF8.self)
    }

    func privateKey(_ jwk: PrivateJWK) throws -> ECPrivateKey<Secp256k1Curve> {
        guard case .external(let key) = jwk.key, let key = key as? ECPrivateKey<Secp256k1Curve> else {
            throw InteropError(description: "not a secp256k1 private key")
        }
        return key
    }

    func sign(_ payload: Data, with key: ECPrivateKey<Secp256k1Curve>, keyID: KeyID?) async throws -> String {
        let signer = try ECDSASigner(privateKey: key, keyID: keyID)
        return try await SimpleJWS.Signed(signing: payload, with: signer, header: JWSHeaderParameters())
            .compactSerialization()
    }

    let challenge = try JSONDecoder().decode(Challenge.self, from: FileHandle.standardInput.readDataToEndOfFile())
    let payload = try bytes(fromHex: challenge.payload)
    var response = Response()

    for jwk in challenge.signingKeys {
        let key = try privateKey(try PrivateJWK(json: Data(jwk.utf8), keyTypes: [.secp256k1]))
        response.signed.append(try await sign(payload, with: key, keyID: nil))
    }

    for index in 0..<3 {
        let keyID = KeyID(rawValue: "generated-\(index)")
        let key = try ECPrivateKey<Secp256k1Curve>()
        let jwk = PrivateJWK(.external(key), metadata: JWKMetadata(keyID: keyID))
        response.generated.append(
            Response.Generated(
                keyID: keyID.rawValue,
                privateJwk: text(try jwk.jsonRepresentation()),
                publicJwk: text(try jwk.publicJWK.jsonRepresentation()),
                thumbprint: try jwk.publicJWK.thumbprint().base64URLEncoded,
                token: try await sign(payload, with: key, keyID: keyID)
            )
        )
    }

    for item in challenge.verify {
        let keys = VerificationKeys(
            jwks: JWKSet(keys: [try JWK(json: Data(item.jwk.utf8), keyTypes: [.secp256k1])]),
            allowing: [.es256k]
        )
        do {
            let verified = try await SimpleJWS.Unverified(compact: item.token).verify(with: keys)
            response.verdicts.append(Response.Verdict(accepted: true, payload: hex(verified.payload)))
        } catch {
            response.verdicts.append(Response.Verdict(accepted: false, payload: nil))
        }
    }

    FileHandle.standardOutput.write(try JSONEncoder().encode(response))
#endif
