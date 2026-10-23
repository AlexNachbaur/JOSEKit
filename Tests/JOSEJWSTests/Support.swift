import Foundation
import JOSECore
import JOSEJWK
import JOSEJWS
import TestSupport
import Testing

// Fixtures here are written by `interop/jws/generate-fixtures.mjs` and
// `interop/jws/generate-certificates.mjs`.

/// The name of an error's enum case, so that tests can assert which case was thrown without
/// having to spell out the case's associated values.
func caseName(_ error: JWSError) -> String {
    // Cases without associated values have no mirror children, and every string conversion of
    // the error goes through its message, so they are named here by hand.
    switch error {
    case .missingProtectedHeader:
        return "missingProtectedHeader"
    case .missingAlgorithm:
        return "missingAlgorithm"
    case .unencodedPayloadNotCritical:
        return "unencodedPayloadNotCritical"
    case .inconsistentPayloadEncoding:
        return "inconsistentPayloadEncoding"
    case .payloadMissing:
        return "payloadMissing"
    case .payloadSuppliedTwice:
        return "payloadSuppliedTwice"
    case .customParametersNotObject:
        return "customParametersNotObject"
    default:
        return Mirror(reflecting: error).children.first?.label ?? "unnamed case: \(error)"
    }
}

/// Runs `body` and returns the name of the `JWSError` case it threw, or `nil` if it returned.
func thrownCase<T>(_ body: () async throws(JWSError) -> T) async -> String? {
    do {
        _ = try await body()
        return nil
    } catch {
        return caseName(error)
    }
}

struct ValidFixture: Decodable {
    struct Token: Decodable {
        let algorithm: String
        let symmetric: Bool
        let jwk: String
        let payload: String
        let compact: String
        let compactDetached: String
        let flattened: String
        let unencodedPayload: String
        let unencodedFlattened: String
        let unencodedFlattenedDetached: String
    }
    struct General: Decodable {
        struct SignerKey: Decodable {
            let algorithm: String
            let jwk: String
        }
        let payload: String
        let json: String
        let signers: [SignerKey]
    }
    let tokens: [Token]
    let general: General
}
