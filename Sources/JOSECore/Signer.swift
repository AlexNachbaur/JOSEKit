import Foundation

/// An error from outside this package (a key store, a hardware token, a remote service), carried
/// inside a typed error as its type name and message so that the typed error can be `Equatable`.
public struct UnderlyingError: Error, Sendable, Equatable, CustomStringConvertible {
    /// The fully qualified type name of the original error.
    public let typeName: String
    public let description: String

    public init(_ error: any Error) {
        typeName = String(reflecting: type(of: error))
        description = String(describing: error)
    }
}

/// Why a ``Signer`` could not produce a signature.
public enum SigningError: Error, Sendable, Equatable {
    /// The key operation itself failed: the key is unavailable, the user cancelled an
    /// authentication prompt, a remote signing service refused. `underlying` is the error
    /// reported by whatever holds the key.
    case keyOperationFailed(algorithm: AlgorithmIdentifier, underlying: UnderlyingError)
    /// The key produced bytes that are not a signature for this algorithm.
    case invalidSignature(SignatureError)
    /// The key produced a DER signature that could not be converted to the JOSE encoding.
    case invalidDERSignature(algorithm: AlgorithmIdentifier, ECDSASignatureError)
}

extension SigningError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .keyOperationFailed(let algorithm, let underlying):
            return "\(algorithm) signing failed in the key operation: \(underlying)"
        case .invalidSignature(let error):
            return "signing key returned an unusable signature: \(error)"
        case .invalidDERSignature(let algorithm, let error):
            return "\(algorithm) signing key returned an unusable DER signature: \(error)"
        }
    }
}

/// Why a ``Verifier`` did not accept a signature.
public enum VerificationError: Error, Sendable, Equatable {
    /// The signature is not valid for this message under this key.
    case signatureMismatch(algorithm: AlgorithmIdentifier)
    /// Verification could not be carried out. This says nothing about whether the signature is
    /// valid.
    case keyOperationFailed(algorithm: AlgorithmIdentifier, underlying: UnderlyingError)
}

extension VerificationError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .signatureMismatch(let algorithm):
            return "\(algorithm) signature does not match the message under the supplied key"
        case .keyOperationFailed(let algorithm, let underlying):
            return "\(algorithm) verification could not be performed: \(underlying)"
        }
    }
}

/// Something that can sign with one specific algorithm.
///
/// The algorithm is an associated type rather than a property so that the `alg` written into a
/// header is derived from the signer and cannot disagree with it.
///
/// Signing is `async` because the key may not be in this process: Secure Enclave keys can wait
/// on user authentication, and keys held by a remote service need a network round trip.
public protocol Signer<Algorithm>: Sendable {
    associatedtype Algorithm: SignatureAlgorithm

    /// Identifies the key to the verifier. Written to the `kid` header parameter when present.
    var keyID: KeyID? { get }

    /// Signs `message`. The signer applies whatever hashing the algorithm specifies; `message`
    /// is the data itself, not a digest.
    func sign(_ message: Data) async throws(SigningError) -> Signature<Algorithm>
}

/// Something that can check signatures made with one specific algorithm.
public protocol Verifier<Algorithm>: Sendable {
    associatedtype Algorithm: SignatureAlgorithm

    /// The identifier of the key this verifier holds, matched against a token's `kid`.
    var keyID: KeyID? { get }

    /// Returns normally only if `signature` is valid for `message`.
    ///
    /// `async` for the same reason ``Signer/sign(_:)`` is: the key may be held by a service or
    /// a hardware token that performs the check itself. None of the built-in verifiers suspends.
    func verify(_ signature: Signature<Algorithm>, for message: Data) async throws(VerificationError)
}
