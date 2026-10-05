/// Application-defined header parameters, encoded alongside the registered ones in a JWS or JWE
/// header.
///
/// Parameters the type does not declare are ignored when a header is read, as RFC 7515 §4 and
/// RFC 7516 §4 require for parameters that are not understood.
public protocol HeaderParameters: Codable, Sendable {
    /// The names of the parameters this type defines that a recipient must understand. When a
    /// header is written, those that are present are listed in `crit`. When one is read, a `crit`
    /// entry is accepted only if it is in this set.
    static var criticalParameterNames: Set<String> { get }
}

extension HeaderParameters {
    public static var criticalParameterNames: Set<String> {
        []
    }
}

/// For headers with registered parameters only.
public struct EmptyHeaderParameters: HeaderParameters, Hashable {
    public init() {}
}
