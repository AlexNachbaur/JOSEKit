// The signature algorithms, and the counterpart's own signing and verification for each, shared
// by the JWK, JWS and JWT scripts.

import crypto from 'node:crypto';

// `joseAlg` is what jose is asked to generate/import with; `algs` are the JOSE identifiers the
// key signs under; `webcrypto` is the algorithm passed to WebCrypto sign/verify, which for ECDSA
// produces and expects IEEE P1363 signatures.
export const ASYMMETRIC = [
    { name: 'P-256', joseAlg: 'ES256', algs: ['ES256'], webcrypto: { name: 'ECDSA', hash: 'SHA-256' } },
    { name: 'P-384', joseAlg: 'ES384', algs: ['ES384'], webcrypto: { name: 'ECDSA', hash: 'SHA-384' } },
    { name: 'P-521', joseAlg: 'ES512', algs: ['ES512'], webcrypto: { name: 'ECDSA', hash: 'SHA-512' } },
    { name: 'Ed25519', joseAlg: 'Ed25519', algs: ['Ed25519', 'EdDSA'], webcrypto: { name: 'Ed25519' } },
];

export const HMAC = [
    { alg: 'HS256', hash: 'sha256', byteCount: 32 },
    { alg: 'HS384', hash: 'sha384', byteCount: 48 },
    { alg: 'HS512', hash: 'sha512', byteCount: 64 },
];

// RSA. One key signs under all six algorithms. The PSS salt length is pinned to the digest
// length for verification as well as signing, because that is what RFC 7518 §3.5 specifies;
// Node's default when verifying is to accept any salt length.
export const RSA = [
    { alg: 'RS256', hash: 'sha256', options: { padding: crypto.constants.RSA_PKCS1_PADDING } },
    { alg: 'RS384', hash: 'sha384', options: { padding: crypto.constants.RSA_PKCS1_PADDING } },
    { alg: 'RS512', hash: 'sha512', options: { padding: crypto.constants.RSA_PKCS1_PADDING } },
    { alg: 'PS256', hash: 'sha256', options: { padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST } },
    { alg: 'PS384', hash: 'sha384', options: { padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST } },
    { alg: 'PS512', hash: 'sha512', options: { padding: crypto.constants.RSA_PKCS1_PSS_PADDING, saltLength: crypto.constants.RSA_PSS_SALTLEN_DIGEST } },
];

export const RSA_ALGORITHMS = RSA.map((spec) => spec.alg);

export function kindForCurve(name) {
    return ASYMMETRIC.find((kind) => kind.name === name);
}

export async function sign(kind, privateKey, message) {
    return Buffer.from(await crypto.subtle.sign(kind.webcrypto, privateKey, message));
}

/** The counterpart's verdict. A signature it cannot parse counts as not accepted. */
export async function verifies(kind, publicKey, message, signature) {
    try {
        return await crypto.subtle.verify(kind.webcrypto, publicKey, signature, message);
    } catch {
        return false;
    }
}

export function hmac(spec, key, message) {
    return crypto.createHmac(spec.hash, key).update(message).digest();
}

export function rsaSpec(alg) {
    return RSA.find((spec) => spec.alg === alg);
}

export function rsaSign(spec, privateKey, message) {
    return crypto.sign(spec.hash, message, { key: privateKey, ...spec.options });
}

export function rsaVerifies(spec, publicKey, message, signature) {
    try {
        return crypto.verify(spec.hash, message, { key: publicKey, ...spec.options }, signature);
    } catch {
        return false;
    }
}
