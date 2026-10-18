import Foundation

/// One PEM block (RFC 7468): a label, and the DER its base64 body decodes to.
///
/// Read strictly: the text must be exactly one block, with only whitespace around it. Headers
/// (`Proc-Type`, `DEK-Info`) mark the legacy OpenSSL encrypted format, which is not supported.
struct PEMDocument {
    let label: String
    let der: Data

    private static let beginPrefix = "-----BEGIN "
    private static let endPrefix = "-----END "
    private static let suffix = "-----"

    init(_ text: String) throws(JWKError) {
        let lines = text.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard lines.count >= 2, let first = lines.first, let last = lines.last else {
            throw .invalidPEM(reason: "there is no BEGIN and END line")
        }
        guard first.hasPrefix(Self.beginPrefix), first.hasSuffix(Self.suffix), first.count > 16 else {
            throw .invalidPEM(reason: "the first line is not a BEGIN line")
        }
        let label = String(first.dropFirst(Self.beginPrefix.count).dropLast(Self.suffix.count))
        guard last == Self.endPrefix + label + Self.suffix else {
            throw .invalidPEM(reason: "the last line is not END \(label)")
        }
        let body = lines.dropFirst().dropLast()
        guard !body.contains(where: { $0.hasPrefix("-----") }) else {
            throw .invalidPEM(reason: "the text holds more than one PEM block")
        }
        guard !body.contains(where: { $0.contains(":") }) else {
            throw .invalidPEM(reason: "the block has headers, as a legacy encrypted key does; these are not supported")
        }
        guard let der = Data(base64Encoded: body.joined()), !der.isEmpty else {
            throw .invalidPEM(reason: "the body is not base64")
        }
        self.label = label
        self.der = der
    }
}

/// Key structures that PEM carries: SubjectPublicKeyInfo (RFC 5280 §4.1.2.7), PKCS#8
/// PrivateKeyInfo (RFC 5208, RFC 5958), and SEC1 ECPrivateKey (RFC 5915).
struct KeyDER {
    private init() {}

    // Algorithms (RFC 3279, RFC 5480, RFC 8410).
    static let rsaEncryption = "1.2.840.113549.1.1.1"
    static let ecPublicKey = "1.2.840.10045.2.1"
    static let ed25519 = "1.3.101.112"
    static let x25519 = "1.3.101.110"
    // Named curves (RFC 5480 §2.1.1.1).
    static let p256 = "1.2.840.10045.3.1.7"
    static let p384 = "1.3.132.0.34"
    static let p521 = "1.3.132.0.35"

    /// RSA's AlgorithmIdentifier parameters are NULL (RFC 3279 §2.3.1); some encoders omit them.
    private static func readRSAParameters(_ algorithm: inout DERReader) throws(JWKError) {
        if algorithm.nextTag == DERReader.null {
            try algorithm.readNull("parameters")
        }
        try algorithm.finish("algorithm")
    }

    // MARK: Public keys

    static func publicKey(subjectPublicKeyInfo der: Data) throws(JWKError) -> JWK.Key {
        var info = try DERReader.wholeSequence(der, "SubjectPublicKeyInfo")
        var algorithm = try info.readConstructed("algorithm")
        let oid = try algorithm.readObjectIdentifier("algorithm")
        let key = try info.readBitString("subjectPublicKey")
        try info.finish("SubjectPublicKeyInfo")
        switch oid {
        case rsaEncryption:
            try readRSAParameters(&algorithm)
            return .rsa(try RSAPublicKey(pkcs1DERRepresentation: key))
        case ecPublicKey:
            let curve = try algorithm.readObjectIdentifier("namedCurve")
            try algorithm.finish("algorithm")
            return try ecPublicKey(x963: key, curve: curve)
        case ed25519:
            // RFC 8410 §3: the parameters are absent.
            try algorithm.finish("algorithm")
            return .ed25519(try Ed25519PublicKey(rawRepresentation: key))
        case x25519:
            try algorithm.finish("algorithm")
            return .x25519(try X25519PublicKey(rawRepresentation: key))
        default:
            throw .unsupportedKeyAlgorithm(oid: oid)
        }
    }

    private static func ecPublicKey(x963: Data, curve: String) throws(JWKError) -> JWK.Key {
        switch curve {
        case p256:
            return .p256(try ECPublicKey<P256Curve>(x963Representation: x963))
        case p384:
            return .p384(try ECPublicKey<P384Curve>(x963Representation: x963))
        case p521:
            return .p521(try ECPublicKey<P521Curve>(x963Representation: x963))
        default:
            throw .unsupportedKeyAlgorithm(oid: curve)
        }
    }

    // MARK: Private keys

    static func privateKey(pkcs8 der: Data) throws(JWKError) -> PrivateJWK.Key {
        var info = try DERReader.wholeSequence(der, "PrivateKeyInfo")
        let version = try info.readUnsignedInteger("version")
        // 0 is PKCS#8 (RFC 5208); 1 is RFC 5958's OneAsymmetricKey, which may add the public key.
        guard version == Data([0x00]) || version == Data([0x01]) else {
            throw .invalidDER(reason: "PrivateKeyInfo version is not 0 or 1")
        }
        var algorithm = try info.readConstructed("privateKeyAlgorithm")
        let oid = try algorithm.readObjectIdentifier("privateKeyAlgorithm")
        let privateKey = try info.readOctetString("privateKey")
        if info.nextTag == DERReader.contextConstructed0 {
            _ = try info.read(tag: DERReader.contextConstructed0, "attributes")
        }
        var publicKeys: [Data] = []
        if info.nextTag == DERReader.contextPrimitive1 {
            publicKeys.append(try info.readBitString(tag: DERReader.contextPrimitive1, "publicKey"))
        }
        try info.finish("PrivateKeyInfo")

        switch oid {
        case rsaEncryption:
            try readRSAParameters(&algorithm)
            let key = try RSAPrivateKey(pkcs1DERRepresentation: privateKey)
            try requireMatch(key.publicKey.pkcs1DERRepresentation, publicKeys, curve: "RSA")
            return .rsa(key)
        case ecPublicKey:
            let curve = try algorithm.readObjectIdentifier("namedCurve")
            try algorithm.finish("privateKeyAlgorithm")
            return try ecPrivateKey(sec1: privateKey, curve: curve, publicKeys: publicKeys)
        case ed25519:
            try algorithm.finish("privateKeyAlgorithm")
            let key = try Ed25519PrivateKey(rawRepresentation: try curvePrivateKey(privateKey))
            try requireMatch(key.publicKey.rawRepresentation, publicKeys, curve: Ed25519PublicKey.curveName)
            return .ed25519(key)
        case x25519:
            try algorithm.finish("privateKeyAlgorithm")
            let key = try X25519PrivateKey(rawRepresentation: try curvePrivateKey(privateKey))
            try requireMatch(key.publicKey.rawRepresentation, publicKeys, curve: X25519PublicKey.curveName)
            return .x25519(key)
        default:
            throw .unsupportedKeyAlgorithm(oid: oid)
        }
    }

    /// RFC 8410 §7: the private key is itself an OCTET STRING inside PKCS#8's.
    private static func curvePrivateKey(_ der: Data) throws(JWKError) -> Data {
        var reader = DERReader(der)
        let key = try reader.readOctetString("CurvePrivateKey")
        try reader.finish("CurvePrivateKey")
        return key
    }

    /// A SEC1 ECPrivateKey. The curve comes from the PKCS#8 algorithm, from the key's own
    /// parameters, or from both, in which case they must agree.
    static func ecPrivateKey(sec1 der: Data, curve outerCurve: String?, publicKeys: [Data]) throws(JWKError)
        -> PrivateJWK.Key
    {
        var key = try DERReader.wholeSequence(der, "ECPrivateKey")
        guard try key.readUnsignedInteger("version") == Data([0x01]) else {
            throw .invalidDER(reason: "ECPrivateKey version is not 1")
        }
        let scalar = try key.readOctetString("privateKey")
        var innerCurve: String?
        if key.nextTag == DERReader.contextConstructed0 {
            var parameters = try key.readConstructed(tag: DERReader.contextConstructed0, "parameters")
            innerCurve = try parameters.readObjectIdentifier("namedCurve")
            try parameters.finish("parameters")
        }
        var embedded = publicKeys
        if key.nextTag == DERReader.contextConstructed1 {
            var wrapper = try key.readConstructed(tag: DERReader.contextConstructed1, "publicKey")
            embedded.append(try wrapper.readBitString("publicKey"))
            try wrapper.finish("publicKey")
        }
        try key.finish("ECPrivateKey")

        if let outerCurve, let innerCurve {
            guard outerCurve == innerCurve else {
                throw .invalidDER(reason: "the key's curve \(innerCurve) differs from the algorithm's \(outerCurve)")
            }
        }
        guard let curve = outerCurve ?? innerCurve else {
            throw .invalidDER(reason: "ECPrivateKey names no curve")
        }
        switch curve {
        case p256:
            return .p256(try ecPrivateKey(P256Curve.self, scalar: scalar, publicKeys: embedded))
        case p384:
            return .p384(try ecPrivateKey(P384Curve.self, scalar: scalar, publicKeys: embedded))
        case p521:
            return .p521(try ecPrivateKey(P521Curve.self, scalar: scalar, publicKeys: embedded))
        default:
            throw .unsupportedKeyAlgorithm(oid: curve)
        }
    }

    private static func ecPrivateKey<Curve: EllipticCurve>(
        _ curve: Curve.Type,
        scalar: Data,
        publicKeys: [Data]
    ) throws(JWKError) -> ECPrivateKey<Curve> {
        let key = try ECPrivateKey<Curve>(rawRepresentation: scalar)
        try requireMatch(key.publicKey.x963Representation, publicKeys, curve: Curve.name)
        return key
    }

    /// A public key that travels with a private key must be that key's public key.
    private static func requireMatch(_ derived: Data, _ embedded: [Data], curve: String) throws(JWKError) {
        for publicKey in embedded where publicKey != derived {
            throw .privateKeyDoesNotMatchPublicKey(curve: curve)
        }
    }
}

extension JWK {
    /// Reads a public key from PEM: `PUBLIC KEY` (SubjectPublicKeyInfo) holding an RSA, P-256,
    /// P-384, P-521, Ed25519 or X25519 key, or `RSA PUBLIC KEY` (PKCS#1).
    public init(pem: String, metadata: JWKMetadata = JWKMetadata()) throws(JWKError) {
        let document = try PEMDocument(pem)
        switch document.label {
        case "PUBLIC KEY":
            self.init(try KeyDER.publicKey(subjectPublicKeyInfo: document.der), metadata: metadata)
        case "RSA PUBLIC KEY":
            self.init(.rsa(try RSAPublicKey(pkcs1DERRepresentation: document.der)), metadata: metadata)
        default:
            throw .wrongPEMType(found: document.label, expected: ["PUBLIC KEY", "RSA PUBLIC KEY"])
        }
    }
}

extension PrivateJWK {
    /// Reads a private key from PEM: `PRIVATE KEY` (PKCS#8) holding an RSA, P-256, P-384, P-521,
    /// Ed25519 or X25519 key, `RSA PRIVATE KEY` (PKCS#1) or `EC PRIVATE KEY` (SEC1). A public key
    /// carried alongside must be the private key's own. Encrypted keys are not supported.
    public init(pem: String, metadata: JWKMetadata = JWKMetadata()) throws(JWKError) {
        let document = try PEMDocument(pem)
        switch document.label {
        case "PRIVATE KEY":
            self.init(try KeyDER.privateKey(pkcs8: document.der), metadata: metadata)
        case "RSA PRIVATE KEY":
            self.init(.rsa(try RSAPrivateKey(pkcs1DERRepresentation: document.der)), metadata: metadata)
        case "EC PRIVATE KEY":
            self.init(try KeyDER.ecPrivateKey(sec1: document.der, curve: nil, publicKeys: []), metadata: metadata)
        default:
            throw .wrongPEMType(found: document.label, expected: ["PRIVATE KEY", "RSA PRIVATE KEY", "EC PRIVATE KEY"])
        }
    }
}
