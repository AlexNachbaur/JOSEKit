import Foundation
import JOSEJWK
import JOSEJWS
import TestSupport

// The fixture here is written by `interop/x509/generate-fixtures.mjs`.

struct ChainsFixture: Decodable {
    struct Case: Decodable {
        struct Verdict: Decodable {
            let accepted: Bool
        }
        let name: String
        /// Names of entries in ``ChainsFixture/anchors``.
        let anchors: [String]
        /// DER certificates, hex, the signer's first.
        let chain: [String]
        /// Seconds since 1970.
        let validationTime: TimeInterval
        /// The signing certificate's key.
        let publicJwk: String
        let privateJwk: String
        let openssl: Verdict

        func anchorDERs(in fixture: ChainsFixture) throws -> [Data] {
            try anchors.map { try fixture.anchor($0) }
        }

        func chainDERs() throws -> [Data] {
            try chain.map { try Data(hex: $0) }
        }
    }

    /// DER certificates, hex, by name.
    let anchors: [String: String]
    let cases: [Case]

    static func load() throws -> ChainsFixture {
        try ChainsFixture(fixture: "chains", in: .module)
    }

    func anchor(_ name: String) throws -> Data {
        guard let hex = anchors[name] else {
            throw FixtureError(description: "no anchor named \(name)")
        }
        return try Data(hex: hex)
    }

    func testCase(_ name: String) throws -> Case {
        guard let found = cases.first(where: { $0.name == name }) else {
            throw FixtureError(description: "no case named \(name)")
        }
        return found
    }
}

/// What a validator made of a chain.
enum Outcome: Equatable, CustomStringConvertible {
    case accepted(JWK)
    case refused
    case unreadable(index: Int)
    case unsupportedKey
    case keyUnusable(JWKError)
    case unexpected(String)

    init(_ validate: () async throws -> JWK) async {
        do {
            self = .accepted(try await validate())
        } catch let error as CertificateValidationError {
            switch error {
            case .trustEvaluationFailed:
                self = .refused
            case .certificateUnreadable(let index):
                self = .unreadable(index: index)
            case .unsupportedKey:
                self = .unsupportedKey
            case .keyUnusable(let error):
                self = .keyUnusable(error)
            }
        } catch {
            self = .unexpected(String(describing: error))
        }
    }

    var description: String {
        switch self {
        case .accepted(let jwk):
            return "accepted \(jwk.keyType)"
        case .refused:
            return "refused"
        case .unreadable(let index):
            return "unreadable at \(index)"
        case .unsupportedKey:
            return "unsupported key"
        case .keyUnusable(let error):
            return "key unusable: \(error)"
        case .unexpected(let description):
            return "unexpected error: \(description)"
        }
    }
}

extension ChainsFixture.Case {
    /// OpenSSL's verdict as an outcome: the signing certificate's key, or a refusal.
    func opensslOutcome() throws -> Outcome {
        guard openssl.accepted else {
            return .refused
        }
        return .accepted(try JWK(json: Data(publicJwk.utf8)))
    }
}
