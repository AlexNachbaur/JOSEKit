import Foundation
import JOSECore
import JOSEJWK

#if canImport(FoundationNetworking)
    import FoundationNetworking
#endif

/// Why ``URLSessionJWKSetProvider`` could not supply a JWK Set.
public enum JWKSetFetchError: Error, Sendable, Equatable {
    case notHTTPS(URL)
    case transportFailure(URL, underlying: UnderlyingError)
    /// The response came from a URL other than the one requested.
    case respondedFromDifferentURL(URL, actual: URL?)
    /// The server answered with a status outside 200–299. A redirect is reported this way too,
    /// on platforms where redirects are refused.
    case unexpectedStatus(URL, status: Int)
    /// The response is larger than ``URLSessionJWKSetProvider/maximumByteCount``.
    case responseTooLarge(URL, maximum: Int)
    case invalidJWKSet(URL, JWKError)
}

extension JWKSetFetchError: CustomStringConvertible {
    public var description: String {
        switch self {
        case .notHTTPS(let url):
            return "JWK Set URL \(url) is not HTTPS"
        case .transportFailure(let url, let underlying):
            return "JWK Set at \(url) could not be fetched: \(underlying)"
        case .respondedFromDifferentURL(let url, let actual):
            return "JWK Set request to \(url) was answered from \(actual.map(\.absoluteString) ?? "an unknown URL")"
        case .unexpectedStatus(let url, let status):
            return "JWK Set at \(url) returned HTTP status \(status)"
        case .responseTooLarge(let url, let maximum):
            return "JWK Set at \(url) is larger than the \(maximum) bytes accepted"
        case .invalidJWKSet(let url, let error):
            return "JWK Set at \(url) is not a valid JWK Set: \(error)"
        }
    }
}

/// Fetches JWK Sets over HTTPS with `URLSession`.
///
/// The body is used only when it comes from the URL requested, so a redirect cannot substitute
/// keys from somewhere the caller did not allow. On Apple platforms redirects are not followed
/// at all, and reading stops as soon as the response exceeds ``maximumByteCount``. The
/// swift-corelibs-foundation `URLSession` used elsewhere offers neither, so there a redirect is
/// followed (and its answer refused) and the size is checked once the body has arrived.
///
/// There is no caching here. Wrap it in ``CachingJWKSetProvider`` so that a key set is not
/// fetched for every token.
public struct URLSessionJWKSetProvider: JWKSetProvider {
    public let session: URLSession
    /// Responses above this size are refused. A JWK Set is a few kilobytes.
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
        let data = try await body(of: request, url: url)
        do {
            return try JWKSet(json: data)
        } catch {
            throw JWKSetFetchError.invalidJWKSet(url, error)
        }
    }

    /// Checks what can be known before the body is read.
    private func check(_ response: URLResponse, url: URL) throws(JWKSetFetchError) {
        // The body must have come from the URL that was asked for, which is the one the caller
        // allow-listed; a response from anywhere else is not used.
        guard response.url == url else {
            throw .respondedFromDifferentURL(url, actual: response.url)
        }
        if let http = response as? HTTPURLResponse, !(200..<300).contains(http.statusCode) {
            throw .unexpectedStatus(url, status: http.statusCode)
        }
        guard response.expectedContentLength <= Int64(maximumByteCount) else {
            throw .responseTooLarge(url, maximum: maximumByteCount)
        }
    }

    #if canImport(FoundationNetworking)
        private func body(of request: URLRequest, url: URL) async throws(JWKSetFetchError) -> Data {
            let data: Data
            let response: URLResponse
            do {
                (data, response) = try await session.data(for: request)
            } catch {
                throw .transportFailure(url, underlying: UnderlyingError(error))
            }
            try check(response, url: url)
            guard data.count <= maximumByteCount else {
                throw .responseTooLarge(url, maximum: maximumByteCount)
            }
            return data
        }
    #else
        private func body(of request: URLRequest, url: URL) async throws(JWKSetFetchError) -> Data {
            let bytes: URLSession.AsyncBytes
            let response: URLResponse
            do {
                (bytes, response) = try await session.bytes(for: request, delegate: RedirectRefusal())
            } catch {
                throw .transportFailure(url, underlying: UnderlyingError(error))
            }
            try check(response, url: url)
            var data = Data()
            do {
                for try await byte in bytes {
                    guard data.count < maximumByteCount else {
                        bytes.task.cancel()
                        throw JWKSetFetchError.responseTooLarge(url, maximum: maximumByteCount)
                    }
                    data.append(byte)
                }
            } catch let error as JWKSetFetchError {
                throw error
            } catch {
                throw .transportFailure(url, underlying: UnderlyingError(error))
            }
            return data
        }
    #endif
}

#if !canImport(FoundationNetworking)
    /// Declines every redirect, so the redirect response itself is what the request returns.
    private final class RedirectRefusal: NSObject, URLSessionTaskDelegate, Sendable {
        func urlSession(
            _ session: URLSession,
            task: URLSessionTask,
            willPerformHTTPRedirection response: HTTPURLResponse,
            newRequest request: URLRequest
        ) async -> URLRequest? {
            nil
        }
    }
#endif

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
