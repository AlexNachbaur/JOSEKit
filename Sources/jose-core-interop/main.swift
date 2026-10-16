// Answers a challenge from `interop/core/closed-loop.mjs` so that the Node counterpart can check
// values produced by JOSECore. Reads the challenge as JSON on stdin and writes the response as
// JSON on stdout. Not part of the library; see `scripts/interop.sh`.

import Foundation
import JOSECore

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

struct InvalidHex: Error, CustomStringConvertible {
    let description: String
}

func bytes(fromHex hex: String) throws -> Data {
    let digits = Array(hex.utf8)
    guard digits.count.isMultiple(of: 2) else {
        throw InvalidHex(description: "hex string has odd length \(digits.count)")
    }
    var output = Data(capacity: digits.count / 2)
    for index in stride(from: 0, to: digits.count, by: 2) {
        guard let byte = UInt8(String(decoding: digits[index..<(index + 2)], as: UTF8.self), radix: 16) else {
            throw InvalidHex(description: "invalid hex at offset \(index)")
        }
        output.append(byte)
    }
    return output
}

func hex(_ data: Data) -> String {
    data.map { byte in
        let digits = String(byte, radix: 16)
        if digits.count == 1 {
            return "0" + digits
        }
        return digits
    }
    .joined()
}

let challenge = try JSONDecoder().decode(Challenge.self, from: FileHandle.standardInput.readDataToEndOfFile())

var response = Response()
for item in challenge.bytesToEncode {
    response.encoded.append(Base64URL.encode(try bytes(fromHex: item)))
}
for item in challenge.stringsToDecode {
    response.decoded.append(hex(try Base64URL.decode(item)))
}
for item in challenge.stringsToQuote {
    response.quoted.append(JSONStringEscaper.quoted(item))
}
for item in challenge.derSignatures {
    let raw = try ECDSASignatureConverter.rawSignature(
        fromDER: try bytes(fromHex: item.signature),
        coordinateByteCount: item.coordinateByteCount
    )
    response.rawFromDER.append(hex(raw))
}
for item in challenge.rawSignatures {
    let der = try ECDSASignatureConverter.derSignature(
        fromRaw: try bytes(fromHex: item.signature),
        coordinateByteCount: item.coordinateByteCount
    )
    response.derFromRaw.append(hex(der))
}

FileHandle.standardOutput.write(try JSONEncoder().encode(response))
