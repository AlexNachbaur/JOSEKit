// Answers a challenge from `interop/core/closed-loop.mjs` so that the Node counterpart can check
// values produced by JOSECore. Reads the challenge as JSON on stdin and writes the response as
// JSON on stdout. Not part of the library; see `scripts/interop.sh`.

import Foundation
import JOSECore
import TestSupport

struct Challenge: Decodable {
    struct SignatureCase: Decodable {
        let coordinateByteCount: Int
        let signature: String
    }

    /// Hex-encoded bytes to encode as base64url.
    let bytesToEncode: [String]
    /// base64url strings, produced by jose, to decode.
    let stringsToDecode: [String]
    /// Strings to write as JSON string literals.
    let stringsToQuote: [String]
    /// Hex-encoded DER signatures to convert to P1363.
    let derSignatures: [SignatureCase]
    /// Hex-encoded P1363 signatures to convert to DER.
    let rawSignatures: [SignatureCase]
}

struct Response: Encodable {
    var encoded: [String] = []
    var decoded: [String] = []
    var quoted: [String] = []
    var rawFromDER: [String] = []
    var derFromRaw: [String] = []
}

let challenge = try Challenge(jsonFrom: .standardInput)

var response = Response()
for item in challenge.bytesToEncode {
    response.encoded.append(String(base64URLEncoding: try Data(hex: item)))
}
for item in challenge.stringsToDecode {
    response.decoded.append(try Data(base64URLEncoded: item).hex)
}
for item in challenge.stringsToQuote {
    response.quoted.append(String(jsonQuoting: item))
}
for item in challenge.derSignatures {
    let raw = try ECDSASignatureConverter(coordinateByteCount: item.coordinateByteCount)
        .rawSignature(fromDER: try Data(hex: item.signature))
    response.rawFromDER.append(raw.hex)
}
for item in challenge.rawSignatures {
    let der = try ECDSASignatureConverter(coordinateByteCount: item.coordinateByteCount)
        .derSignature(fromRaw: try Data(hex: item.signature))
    response.derFromRaw.append(der.hex)
}

try response.writeJSON(to: .standardOutput)
