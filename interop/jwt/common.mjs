// Shared by the fixture generator and the closed-loop check.

import crypto from 'node:crypto';
import { createRequire } from 'node:module';

const require = createRequire(import.meta.url);
export const joseVersion = require('jose/package.json').version;

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

export function flipLastBit(buffer) {
    const copy = Buffer.from(buffer);
    copy[copy.length - 1] ^= 0x01;
    return copy;
}

export const RSA_ALGORITHMS = ['RS256', 'RS384', 'RS512', 'PS256', 'PS384', 'PS512'];
