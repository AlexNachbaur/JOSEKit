// Answers a challenge from `interop/jwe/closed-loop.mjs` so that the Node counterpart can decrypt JWEs
// produced by JOSEJWE, and can check this package's results on JWEs the counterpart made. Reads
// the challenge as JSON on stdin and writes the response as JSON on stdout. Not part of the
// library; see `scripts/interop.sh`.

import Foundation
import JOSECore
import JOSEJWE
import JOSEJWK

struct Challenge: Decodable {
    struct EncryptCase: Decodable {
        let algorithm: String
        let encryption: String
        /// The recipient's public JWK, or the shared symmetric JWK.
        let jwk: String
    }
    struct DecryptCase: Decodable {
        let algorithm: String
        /// The private or symmetric JWK to decrypt with.
        let jwk: String
        let serialization: String
        let token: String
    }

    /// Hex-encoded plaintext for every JWE this package is asked to produce.
    let plaintext: String
    let additionalData: String
    let encrypt: [EncryptCase]
    /// Recipients for one JWE addressed to all of them.
    let multiple: [EncryptCase]
    /// JWEs made by the counterpart, some intact and some not, for this package to open.
    let decrypt: [DecryptCase]

    /// Compression (`zip: DEF`): a shared A256KW key, a plaintext for this package to compress,
    /// and JWEs the counterpart compressed for this package to open.
    struct Compression: Decodable {
        struct Token: Decodable {
            let token: String
        }
        let jwk: String
        let plaintext: String
        let tokens: [Token]
    }
    let compression: Compression
}

struct Response: Encodable {
    struct Produced: Encodable {
        let compact: String
        /// The same recipient again, in flattened JSON with additional authenticated data.
        let flattened: String
    }
    struct Outcome: Encodable {
        let accepted: Bool
        let plaintext: String?
    }

    var produced: [Produced] = []
    var multiple = ""
    var outcomes: [Outcome] = []
    /// The compression plaintext, compressed and encrypted by this package.
    var compressed = ""
    var compressedOutcomes: [Outcome] = []
}

struct InteropError: Error, CustomStringConvertible {
    let description: String
}

func bytes(fromHex hex: String) throws -> Data {
    let digits = Array(hex.utf8)
    guard digits.count.isMultiple(of: 2) else {
        throw InteropError(description: "hex string has odd length \(digits.count)")
    }
    var output = Data(capacity: digits.count / 2)
    for index in stride(from: 0, to: digits.count, by: 2) {
        guard let byte = UInt8(String(decoding: digits[index..<(index + 2)], as: UTF8.self), radix: 16) else {
            throw InteropError(description: "invalid hex at offset \(index)")
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

func encrypter(algorithm: String, jwk: String, keyID: KeyID? = nil) throws -> AnyKeyEncrypter {
    let json = Data(jwk.utf8)
    func secret() throws -> SymmetricKeyMaterial {
        try SymmetricJWK(json: json).key
    }
    func publicKey() throws -> JWK {
        var key = try JWK(json: json)
        key.metadata.keyID = keyID
        return key
    }
    switch algorithm {
    case "dir":
        return AnyKeyEncrypter(DirectEncrypter(key: try secret(), keyID: keyID))
    case "A128KW":
        return AnyKeyEncrypter(try AESKeyWrapEncrypter<A128KW>(key: try secret(), keyID: keyID))
    case "A192KW":
        return AnyKeyEncrypter(try AESKeyWrapEncrypter<A192KW>(key: try secret(), keyID: keyID))
    case "A256KW":
        return AnyKeyEncrypter(try AESKeyWrapEncrypter<A256KW>(key: try secret(), keyID: keyID))
    case "A128GCMKW":
        return AnyKeyEncrypter(try AESGCMKeyWrapEncrypter<A128GCMKW>(key: try secret(), keyID: keyID))
    case "A192GCMKW":
        return AnyKeyEncrypter(try AESGCMKeyWrapEncrypter<A192GCMKW>(key: try secret(), keyID: keyID))
    case "A256GCMKW":
        return AnyKeyEncrypter(try AESGCMKeyWrapEncrypter<A256GCMKW>(key: try secret(), keyID: keyID))
    case "ECDH-ES":
        return AnyKeyEncrypter(try ECDHESEncrypter<ECDHES>(jwk: try publicKey()))
    case "ECDH-ES+A128KW":
        return AnyKeyEncrypter(try ECDHESEncrypter<ECDHESA128KW>(jwk: try publicKey()))
    case "ECDH-ES+A192KW":
        return AnyKeyEncrypter(try ECDHESEncrypter<ECDHESA192KW>(jwk: try publicKey()))
    case "ECDH-ES+A256KW":
        return AnyKeyEncrypter(try ECDHESEncrypter<ECDHESA256KW>(jwk: try publicKey()))
    case "RSA-OAEP":
        return AnyKeyEncrypter(try RSAEncrypter<RSAOAEP>(jwk: try publicKey()))
    case "RSA-OAEP-256":
        return AnyKeyEncrypter(try RSAEncrypter<RSAOAEP256>(jwk: try publicKey()))
    case "PBES2-HS256+A128KW":
        return AnyKeyEncrypter(
            try PBES2Encrypter<PBES2HS256A128KW>(password: try secret().rawRepresentation, keyID: keyID)
        )
    case "PBES2-HS384+A192KW":
        return AnyKeyEncrypter(
            try PBES2Encrypter<PBES2HS384A192KW>(password: try secret().rawRepresentation, keyID: keyID)
        )
    case "PBES2-HS512+A256KW":
        return AnyKeyEncrypter(
            try PBES2Encrypter<PBES2HS512A256KW>(password: try secret().rawRepresentation, keyID: keyID)
        )
    default:
        throw InteropError(description: "unsupported algorithm \(algorithm)")
    }
}

func ecdhDecrypter<Algorithm: ECDHESAlgorithm>(_ algorithm: Algorithm.Type, _ jwk: PrivateJWK) throws -> AnyKeyDecrypter
{
    switch jwk.key {
    case .p256(let key):
        return AnyKeyDecrypter(ECDHESDecrypter<Algorithm, ECPrivateKey<P256Curve>>(privateKey: key))
    case .p384(let key):
        return AnyKeyDecrypter(ECDHESDecrypter<Algorithm, ECPrivateKey<P384Curve>>(privateKey: key))
    case .p521(let key):
        return AnyKeyDecrypter(ECDHESDecrypter<Algorithm, ECPrivateKey<P521Curve>>(privateKey: key))
    case .x25519(let key):
        return AnyKeyDecrypter(ECDHESDecrypter<Algorithm, X25519PrivateKey>(privateKey: key))
    case .ed25519, .rsa:
        throw InteropError(description: "not an ECDH key")
    }
}

func decrypter(algorithm: String, jwk: String) throws -> AnyKeyDecrypter {
    let json = Data(jwk.utf8)
    func secret() throws -> SymmetricKeyMaterial {
        try SymmetricJWK(json: json).key
    }
    func rsa() throws -> RSAPrivateKey {
        guard case .rsa(let key) = try PrivateJWK(json: json).key else {
            throw InteropError(description: "not an RSA key")
        }
        return key
    }
    switch algorithm {
    case "dir":
        return AnyKeyDecrypter(DirectDecrypter(key: try secret()))
    case "A128KW":
        return AnyKeyDecrypter(try AESKeyWrapDecrypter<A128KW>(key: try secret()))
    case "A192KW":
        return AnyKeyDecrypter(try AESKeyWrapDecrypter<A192KW>(key: try secret()))
    case "A256KW":
        return AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(key: try secret()))
    case "A128GCMKW":
        return AnyKeyDecrypter(try AESGCMKeyWrapDecrypter<A128GCMKW>(key: try secret()))
    case "A192GCMKW":
        return AnyKeyDecrypter(try AESGCMKeyWrapDecrypter<A192GCMKW>(key: try secret()))
    case "A256GCMKW":
        return AnyKeyDecrypter(try AESGCMKeyWrapDecrypter<A256GCMKW>(key: try secret()))
    case "ECDH-ES":
        return try ecdhDecrypter(ECDHES.self, try PrivateJWK(json: json))
    case "ECDH-ES+A128KW":
        return try ecdhDecrypter(ECDHESA128KW.self, try PrivateJWK(json: json))
    case "ECDH-ES+A192KW":
        return try ecdhDecrypter(ECDHESA192KW.self, try PrivateJWK(json: json))
    case "ECDH-ES+A256KW":
        return try ecdhDecrypter(ECDHESA256KW.self, try PrivateJWK(json: json))
    case "RSA-OAEP":
        return AnyKeyDecrypter(try RSADecrypter<RSAOAEP>(privateKey: try rsa()))
    case "RSA-OAEP-256":
        return AnyKeyDecrypter(try RSADecrypter<RSAOAEP256>(privateKey: try rsa()))
    case "PBES2-HS256+A128KW":
        return AnyKeyDecrypter(PBES2Decrypter<PBES2HS256A128KW>(password: try secret().rawRepresentation))
    case "PBES2-HS384+A192KW":
        return AnyKeyDecrypter(PBES2Decrypter<PBES2HS384A192KW>(password: try secret().rawRepresentation))
    case "PBES2-HS512+A256KW":
        return AnyKeyDecrypter(PBES2Decrypter<PBES2HS512A256KW>(password: try secret().rawRepresentation))
    default:
        throw InteropError(description: "unsupported algorithm \(algorithm)")
    }
}

func seal(
    _ plaintext: Data,
    to recipients: [AnyKeyEncrypter],
    encryption: String,
    additionalData: Data? = nil
) async throws -> SimpleJWE.Encrypted {
    let header = JWEHeaderParameters(type: "example+jwe")
    switch encryption {
    case "A128GCM":
        return try await SimpleJWE.Encrypted(
            encrypting: plaintext,
            to: recipients,
            using: .a128gcm,
            header: header,
            additionalAuthenticatedData: additionalData
        )
    case "A192GCM":
        return try await SimpleJWE.Encrypted(
            encrypting: plaintext,
            to: recipients,
            using: .a192gcm,
            header: header,
            additionalAuthenticatedData: additionalData
        )
    case "A256GCM":
        return try await SimpleJWE.Encrypted(
            encrypting: plaintext,
            to: recipients,
            using: .a256gcm,
            header: header,
            additionalAuthenticatedData: additionalData
        )
    case "A128CBC-HS256":
        return try await SimpleJWE.Encrypted(
            encrypting: plaintext,
            to: recipients,
            using: .a128cbcHS256,
            header: header,
            additionalAuthenticatedData: additionalData
        )
    case "A192CBC-HS384":
        return try await SimpleJWE.Encrypted(
            encrypting: plaintext,
            to: recipients,
            using: .a192cbcHS384,
            header: header,
            additionalAuthenticatedData: additionalData
        )
    case "A256CBC-HS512":
        return try await SimpleJWE.Encrypted(
            encrypting: plaintext,
            to: recipients,
            using: .a256cbcHS512,
            header: header,
            additionalAuthenticatedData: additionalData
        )
    default:
        throw InteropError(description: "unsupported content encryption \(encryption)")
    }
}

let challenge = try JSONDecoder().decode(Challenge.self, from: FileHandle.standardInput.readDataToEndOfFile())
let plaintext = try bytes(fromHex: challenge.plaintext)
let additionalData = try bytes(fromHex: challenge.additionalData)
var response = Response()

for item in challenge.encrypt {
    let recipient = try encrypter(algorithm: item.algorithm, jwk: item.jwk)
    let compact = try await seal(plaintext, to: [recipient], encryption: item.encryption).compactSerialization()
    let flattened = try await seal(
        plaintext,
        to: [recipient],
        encryption: item.encryption,
        additionalData: additionalData
    )
    .flattenedJSONSerialization()
    response.produced.append(Response.Produced(compact: compact, flattened: String(decoding: flattened, as: UTF8.self)))
}

var recipients: [AnyKeyEncrypter] = []
for (index, item) in challenge.multiple.enumerated() {
    recipients.append(
        try encrypter(algorithm: item.algorithm, jwk: item.jwk, keyID: KeyID(rawValue: "recipient-\(index)"))
    )
}
if let encryption = challenge.multiple.first?.encryption {
    let sealed = try await seal(plaintext, to: recipients, encryption: encryption, additionalData: additionalData)
    response.multiple = String(decoding: try sealed.generalJSONSerialization(), as: UTF8.self)
}

for item in challenge.decrypt {
    let keys = DecryptionKeys([try decrypter(algorithm: item.algorithm, jwk: item.jwk)])
    do {
        let jwe: SimpleJWE.Encrypted
        switch item.serialization {
        case "compact":
            jwe = try SimpleJWE.Encrypted(compact: item.token)
        case "json":
            jwe = try SimpleJWE.Encrypted(json: Data(item.token.utf8))
        default:
            throw InteropError(description: "unknown serialization \(item.serialization)")
        }
        let decrypted = try await jwe.decrypt(with: keys)
        response.outcomes.append(Response.Outcome(accepted: true, plaintext: hex(decrypted.plaintext)))
    } catch is JWEError {
        response.outcomes.append(Response.Outcome(accepted: false, plaintext: nil))
    }
}

// `zip` does not exist on Windows (no system zlib); the interop check runs on Linux and macOS.
#if !os(Windows)
    let zipKey = try SymmetricJWK(json: Data(challenge.compression.jwk.utf8))
    response.compressed = try await SimpleJWE.Encrypted(
        encrypting: try bytes(fromHex: challenge.compression.plaintext),
        to: try AESKeyWrapEncrypter<A256KW>(jwk: zipKey),
        using: .a256gcm,
        header: JWEHeaderParameters(compression: .deflate)
    ).compactSerialization()
    let zipKeys = DecryptionKeys([AnyKeyDecrypter(try AESKeyWrapDecrypter<A256KW>(jwk: zipKey))])
    for item in challenge.compression.tokens {
        do {
            let decrypted = try await SimpleJWE.Encrypted(compact: item.token).decrypt(with: zipKeys)
            response.compressedOutcomes.append(Response.Outcome(accepted: true, plaintext: hex(decrypted.plaintext)))
        } catch {
            response.compressedOutcomes.append(Response.Outcome(accepted: false, plaintext: nil))
        }
    }
#endif

FileHandle.standardOutput.write(try JSONEncoder().encode(response))
