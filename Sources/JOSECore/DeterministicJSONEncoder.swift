import Foundation

extension JSONEncoder {
    /// An encoder whose output for a given value is always the same bytes: keys sorted, and `/`
    /// left unescaped. Headers and claims are encoded with it.
    package static func deterministic() -> JSONEncoder {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys, .withoutEscapingSlashes]
        return encoder
    }
}
