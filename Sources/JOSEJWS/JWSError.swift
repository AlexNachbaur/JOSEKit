import JOSECore
import JOSEJWK

/// Why a JWS could not be parsed, verified or produced.
public enum JWSError: Error, Sendable, Equatable {
    // MARK: Parsing

    /// A compact JWS is exactly three segments separated by `.`.
    case invalidCompactSerialization(segmentCount: Int)
    /// A compact JWS must have a protected header.
    case missingProtectedHeader
    /// `part` names the base64url-encoded part: "protected header", "payload" or "signature".
    case invalidBase64URL(part: String, Base64URLError)
    /// The part contains `=`. JWS uses base64url without padding (RFC 7515 §2).
    case paddingNotAllowed(part: String)
    /// The JWS JSON Serialization is not a JSON object with unique member names.
    case invalidJSONStructure(JSONStructureError)
    /// The JWS JSON Serialization has a member of the wrong type, is missing a required member,
    /// or mixes the flattened and general forms.
    case invalidJSONSerialization(reason: String)
    /// The header is not a JSON object with unique member names.
    case invalidHeaderStructure(JSONStructureError)
    case invalidHeaderJSON(description: String)
    /// Neither the protected nor the unprotected header has `alg`.
    case missingAlgorithm
    case headerParameterWrongType(name: String, expected: String)
    /// The same parameter appears in both the protected and the unprotected header.
    case headerParameterInBothHeaders(name: String)
    /// A parameter that must be integrity-protected is in the unprotected header.
    case headerParameterNotProtected(name: String)
    /// `crit` is empty, repeats a name, names a parameter defined by the JWS or JWA
    /// specifications, or names a parameter that is not in the header (RFC 7515 §4.1.11).
    case invalidCritical(reason: String)
    /// `crit` names an extension that neither this package nor the custom header type understands.
    case unsupportedCriticalParameter(name: String)
    /// `b64` is present but not listed in `crit`, which RFC 7797 §6 requires.
    case unencodedPayloadNotCritical
    /// The `jwk` header parameter is not a usable public key.
    case invalidJWKParameter(JWKError)
    /// The header could not be decoded as the custom header type.
    case invalidCustomParameters(description: String)
    /// Signatures in one JWS disagree about `b64`, which RFC 7797 §3 forbids.
    case inconsistentPayloadEncoding

    // MARK: Payload

    /// The JWS has no payload and none was supplied for verification.
    case payloadMissing
    /// A detached payload was supplied, but the JWS carries one of its own.
    case payloadSuppliedTwice
    /// An unencoded payload cannot be written in this serialization: it contains a character the
    /// compact form cannot carry, or is not UTF-8.
    case unencodedPayloadNotRepresentable(reason: String)

    // MARK: Verification

    /// No verifier was supplied for the algorithm the JWS names. `offered` lists the algorithms
    /// that were.
    case noVerifierForAlgorithm(algorithm: AlgorithmIdentifier, offered: [AlgorithmIdentifier])
    /// Verifiers for the algorithm exist, but all of them are for other key IDs.
    case noVerifierForKeyID(keyID: KeyID, algorithm: AlgorithmIdentifier)
    /// The signature bytes cannot be a signature for this algorithm.
    case malformedSignature(SignatureError)
    /// Every candidate key was tried and none accepted the signature.
    case signatureInvalid(algorithm: AlgorithmIdentifier, keyID: KeyID?)
    /// A verifier could not carry out the check.
    case verificationFailed(VerificationError)
    /// The JWS has several signatures and none verified. One reason per signature, in order.
    case noSignatureVerified(reasons: [JWSError])
    /// The JWS has several signatures and none of their headers could be read, so none could
    /// ever verify. One reason per signature, in order.
    case noUsableSignature(reasons: [JWSError])
    /// Keys could not be obtained from the header's `jku`, `x5c` or `jwk`.
    case keyResolutionFailed(KeyResolutionError)

    // MARK: Signing

    case signingFailed(SigningError)
    case headerEncodingFailed(description: String)
    /// The custom header type encodes a parameter whose name this package owns.
    case customParameterCollision(name: String)
    /// The custom header type did not encode to a JSON object.
    case customParametersNotObject
    /// The compact and flattened serializations hold exactly one signature.
    case singleSignatureRequired(serialization: String, count: Int)
}

extension JWSError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .invalidCompactSerialization(let segmentCount):
            return "compact JWS has \(segmentCount) segments; exactly 3 are required"
        case .missingProtectedHeader:
            return "compact JWS has an empty protected header"
        case .invalidBase64URL(let part, let error):
            return "JWS \(part) is not valid base64url: \(error)"
        case .paddingNotAllowed(let part):
            return "JWS \(part) contains '='; JWS base64url is unpadded"
        case .invalidJSONStructure(let error):
            return "JWS JSON serialization is not a well-formed JSON object: \(error)"
        case .invalidJSONSerialization(let reason):
            return "JWS JSON serialization is invalid: \(reason)"
        case .invalidHeaderStructure(let error):
            return "JWS header is not a well-formed JSON object: \(error)"
        case .invalidHeaderJSON(let description):
            return "JWS header could not be decoded: \(description)"
        case .missingAlgorithm:
            return "JWS header has no \"alg\" parameter"
        case .headerParameterWrongType(let name, let expected):
            return "JWS header parameter \"\(name)\" must be \(expected)"
        case .headerParameterInBothHeaders(let name):
            return "JWS header parameter \"\(name)\" appears in both the protected and unprotected headers"
        case .headerParameterNotProtected(let name):
            return "JWS header parameter \"\(name)\" must be in the protected header"
        case .invalidCritical(let reason):
            return "JWS \"crit\" header parameter is invalid: \(reason)"
        case .unsupportedCriticalParameter(let name):
            return "JWS marks header parameter \"\(name)\" as critical, and it is not understood"
        case .unencodedPayloadNotCritical:
            return "JWS header has \"b64\" without listing it in \"crit\""
        case .invalidJWKParameter(let error):
            return "JWS \"jwk\" header parameter is not a usable public key: \(error)"
        case .invalidCustomParameters(let description):
            return "JWS header could not be decoded as the custom header type: \(description)"
        case .inconsistentPayloadEncoding:
            return "signatures in this JWS disagree about the \"b64\" header parameter"
        case .payloadMissing:
            return "JWS has a detached payload and none was supplied"
        case .payloadSuppliedTwice:
            return "a detached payload was supplied for a JWS that carries its own payload"
        case .unencodedPayloadNotRepresentable(let reason):
            return "unencoded JWS payload cannot be serialized: \(reason)"
        case .noVerifierForAlgorithm(let algorithm, let offered):
            return "JWS is signed with \(algorithm), for which no verifier was supplied "
                + "(supplied: \(offered.map(\.rawValue).sorted().joined(separator: ", ")))"
        case .noVerifierForKeyID(let keyID, let algorithm):
            return "no \(algorithm) verifier was supplied for key ID \"\(keyID)\""
        case .malformedSignature(let error):
            return "JWS signature is malformed: \(error)"
        case .signatureInvalid(let algorithm, let keyID):
            if let keyID {
                return "\(algorithm) signature is not valid under any supplied key for key ID \"\(keyID)\""
            }
            return "\(algorithm) signature is not valid under any supplied key"
        case .verificationFailed(let error):
            return "JWS verification could not be performed: \(error)"
        case .noSignatureVerified(let reasons):
            return "none of the JWS's \(reasons.count) signatures verified: "
                + reasons.map(\.description).joined(separator: "; ")
        case .noUsableSignature(let reasons):
            return "none of the JWS's \(reasons.count) signatures has a usable header: "
                + reasons.map(\.description).joined(separator: "; ")
        case .keyResolutionFailed(let error):
            return "JWS verification keys could not be resolved from the header: \(error)"
        case .signingFailed(let error):
            return "JWS signing failed: \(error)"
        case .headerEncodingFailed(let description):
            return "JWS header could not be encoded: \(description)"
        case .customParameterCollision(let name):
            return "custom header type encodes \"\(name)\", which is a parameter this package sets"
        case .customParametersNotObject:
            return "custom header type did not encode to a JSON object"
        case .singleSignatureRequired(let serialization, let count):
            return "the \(serialization) serialization holds one signature; this JWS has \(count)"
        }
    }
}
