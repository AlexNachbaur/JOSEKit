import Foundation
import JOSECore
import JOSEJWE
import JOSEJWK
import TestSupport
import Testing

// Fixtures here are written by `interop/jwe/generate-fixtures.mjs`.

/// Runs `body` and returns the error it threw, or `nil` if it returned.
func thrown<T>(_ body: () async throws(JWEError) -> T) async -> JWEError? {
    do {
        _ = try await body()
        return nil
    } catch {
        return error
    }
}
