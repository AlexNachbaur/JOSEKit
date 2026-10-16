import Foundation

/// Why bytes were refused as a signature for a particular algorithm.
public enum SignatureError: Error, Sendable, Equatable {
    case wrongLength(algorithm: AlgorithmIdentifier, expected: Int, found: Int)
}

extension SignatureError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .wrongLength(let algorithm, let expected, let found):
            return "\(algorithm) signature is \(found) bytes; expected \(expected)"
        }
    }
}

/// A signature in the encoding JOSE uses for `Algorithm`.
///
/// The algorithm is part of the type, so an ES256 signature cannot be handed to an ES384
/// verifier, and a DER-encoded ECDSA signature cannot be mistaken for a JOSE one: it has to come
/// in through ``init(derRepresentation:)``.
///
/// Deliberately not `Equatable`. For MAC algorithms a signature is checked by comparing it with a
/// recomputed one, and `==` would make the variable-time comparison the easiest one to write.
public struct Signature<Algorithm: SignatureAlgorithm>: Sendable {
    /// The signature bytes exactly as they are base64url-encoded into a JWS.
    public let rawRepresentation: Data

    /// Wraps signature bytes that are already in JOSE encoding, checking their length against
    /// ``SignatureAlgorithm/signatureByteCount`` when the algorithm defines one.
    public init(rawRepresentation: Data) throws(SignatureError) {
        if let expected = Algorithm.signatureByteCount {
            guard rawRepresentation.count == expected else {
                throw .wrongLength(
                    algorithm: Algorithm.identifier,
                    expected: expected,
                    found: rawRepresentation.count
                )
            }
        }
        self.rawRepresentation = rawRepresentation
    }
}

extension Signature where Algorithm: ECDSASignatureAlgorithm {
    /// Converts a DER-encoded ECDSA signature, as produced by Security.framework and most
    /// hardware keys, to the JOSE encoding.
    public init(derRepresentation: Data) throws(ECDSASignatureError) {
        rawRepresentation = try ECDSASignatureConverter.rawSignature(
            fromDER: derRepresentation,
            coordinateByteCount: Algorithm.coordinateByteCount
        )
    }

    /// The signature as ASN.1 DER.
    public var derRepresentation: Data {
        get throws(ECDSASignatureError) {
            try ECDSASignatureConverter.derSignature(
                fromRaw: rawRepresentation,
                coordinateByteCount: Algorithm.coordinateByteCount
            )
        }
    }
}
