/// Application-defined header parameters, encoded alongside the registered ones in a JWS or JWE
/// header.
///
/// A conforming type is decoded from the header's JSON, so it should treat every parameter as
/// optional and tolerate parameters it does not declare; the packages that read headers
/// (JOSEJWS, JOSEJWE) leave unknown, non-critical parameters to be ignored as RFC 7515 §4 and
/// RFC 7516 §4 require.
public protocol HeaderParameters: Codable, Sendable {
    /// The names of the parameters this type defines that a recipient must understand. The
    /// packages that write headers list those that are present in `crit`; the packages that read
    /// headers accept a `crit` entry only if it is in this set.
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
