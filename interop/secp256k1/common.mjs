// Shared by the fixture generator and the closed-loop check.
//
// jose 6 has no ES256K: it signs through WebCrypto, which has no secp256k1. Keys and signatures
// here come from Node's own crypto module, which is OpenSSL. jose still supplies base64url and
// RFC 7638 thumbprints, which do not depend on the curve.

import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { base64url } from 'jose';

const require = createRequire(import.meta.url);
export const joseVersion = require('jose/package.json').version;

/** The order of secp256k1's base point (SEC 2 §2.4.1). */
export const ORDER = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
export const HALF_ORDER = ORDER >> 1n;

export function generateKeyPair() {
    return crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' });
}

export function exportJwk(key) {
    return key.export({ format: 'jwk' });
}

/** OpenSSL's ES256K signature, `r || s`, over `signingInput`. OpenSSL does not normalise S. */
export function sign(privateKey, signingInput) {
    return crypto.sign('sha256', Buffer.from(signingInput), { key: privateKey, dsaEncoding: 'ieee-p1363' });
}

/** OpenSSL's verdict. A signature it cannot parse counts as not accepted. */
export function verifies(publicKey, signingInput, signature) {
    try {
        return crypto.verify('sha256', Buffer.from(signingInput), { key: publicKey, dsaEncoding: 'ieee-p1363' }, signature);
    } catch {
        return false;
    }
}

function toBytes(value) {
    return Buffer.from(value.toString(16).padStart(64, '0'), 'hex');
}

export function sOf(signature) {
    return BigInt('0x' + signature.subarray(32).toString('hex'));
}

export function withR(signature, r) {
    return Buffer.concat([toBytes(r), signature.subarray(32)]);
}

export function withS(signature, s) {
    return Buffer.concat([signature.subarray(0, 32), toBytes(s)]);
}

export function isLowS(signature) {
    return sOf(signature) <= HALF_ORDER;
}

/** The same signature in its other S form: `(r, n - s)` is valid exactly when `(r, s)` is. */
export function otherForm(signature) {
    return withS(signature, ORDER - sOf(signature));
}

export function signingInput(header, payload) {
    return `${base64url.encode(JSON.stringify(header))}.${base64url.encode(payload)}`;
}

export function compact(input, signature) {
    return `${input}.${base64url.encode(signature)}`;
}

export function flipLastBit(buffer) {
    const copy = Buffer.from(buffer);
    copy[copy.length - 1] ^= 0x01;
    return copy;
}
