import Foundation
import JOSECore
import JOSEJWK

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Why ``URLSessionJWKSetProvider`` could not supply a JWK Set.
public enum JWKSetFetchError: Error, Sendable {
    case notHTTPS(URL)
    case transportFailure(URL, underlying: any Error)
    case unexpectedStatus(URL, status: Int)
    /// The response is larger than ``URLSessionJWKSetProvider/maximumByteCount``.
    case responseTooLarge(URL, byteCount: Int, maximum: Int)
    case invalidJWKSet(URL, JWKError)
}

extension JWKSetFetchError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .notHTTPS(let url):
            return "JWK Set URL \(url) is not HTTPS"
        case .transportFailure(let url, let underlying):
            return "JWK Set at \(url) could not be fetched: \(underlying)"
        case .unexpectedStatus(let url, let status):
            return "JWK Set at \(url) returned HTTP status \(status)"
        case .responseTooLarge(let url, let byteCount, let maximum):
            return "JWK Set at \(url) is \(byteCount) bytes; at most \(maximum) are accepted"
        case .invalidJWKSet(let url, let error):
            return "JWK Set at \(url) is not a valid JWK Set: \(error)"
        }
    }
}

/// Fetches JWK Sets over HTTPS with `URLSession`.
///
/// There is no caching here. Wrap it in ``CachingJWKSetProvider`` so that a key set is not
/// fetched for every token.
public struct URLSessionJWKSetProvider: JWKSetProvider {
    public let session: URLSession
    /// Responses above this size are refused. A JWK Set is a few kilobytes; a limit keeps a
    /// misconfigured or hostile endpoint from filling memory.
    public let maximumByteCount: Int
    public let timeout: TimeInterval

    public init(session: URLSession = .shared, maximumByteCount: Int = 1_048_576, timeout: TimeInterval = 15) {
        self.session = session
        self.maximumByteCount = maximumByteCount
        self.timeout = timeout
    }

    public func jwkSet(at url: URL) async throws -> JWKSet {
        guard url.scheme?.lowercased() == "https" else {
            throw JWKSetFetchError.notHTTPS(url)
        }
        var request = URLRequest(url: url, timeoutInterval: timeout)
        request.setValue("application/json, application/jwk-set+json", forHTTPHeaderField: "Accept")
        let data: Data
        let response: URLResponse
        do {
            (data, response) = try await session.data(for: request)
        } catch {
            throw JWKSetFetchError.transportFailure(url, underlying: error)
        }
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw JWKSetFetchError.unexpectedStatus(url, status: http.statusCode)
        }
        guard data.count <= maximumByteCount else {
            throw JWKSetFetchError.responseTooLarge(url, byteCount: data.count, maximum: maximumByteCount)
        }
        do {
            return try JWKSet(json: data)
        } catch {
            throw JWKSetFetchError.invalidJWKSet(url, error)
        }
    }
}

/// Remembers each JWK Set for a while, so that one fetch serves many tokens.
///
/// A set is refreshed when it is older than ``timeToLive``. There is deliberately no
/// refresh-on-unknown-`kid`: that would let anyone who can send a token make you hit the
/// endpoint as often as they like.
public actor CachingJWKSetProvider: JWKSetProvider {
    private struct Entry {
        let set: JWKSet
        let fetchedAt: Date
    }

    private let upstream: any JWKSetProvider
    private let timeToLive: TimeInterval
    private let clock: @Sendable () -> Date
    private var entries: [URL: Entry] = [:]
    private var inFlight: [URL: Task<JWKSet, any Error>] = [:]

    public init(
        _ upstream: any JWKSetProvider,
        timeToLive: TimeInterval = 300,
        clock: @escaping @Sendable () -> Date = { Date() }
    ) {
        self.upstream = upstream
        self.timeToLive = timeToLive
        self.clock = clock
    }

    public func jwkSet(at url: URL) async throws -> JWKSet {
        if let entry = entries[url], clock().timeIntervalSince(entry.fetchedAt) < timeToLive {
            return entry.set
        }
        // Concurrent requests for the same URL share one fetch.
        if let task = inFlight[url] {
            return try await task.value
        }
        let upstream = upstream
        let task = Task { try await upstream.jwkSet(at: url) }
        inFlight[url] = task
        defer { inFlight[url] = nil }
        let set = try await task.value
        entries[url] = Entry(set: set, fetchedAt: clock())
        return set
    }

    /// Forgets every cached set.
    public func invalidate() {
        entries.removeAll()
    }
}
