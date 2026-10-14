// Shared ECDSA helpers for the fixture generator and the closed-loop check.

import crypto from 'node:crypto';

export const CURVES = [
    { name: 'P-256', hash: 'sha256', coordinateByteCount: 32 },
    { name: 'P-384', hash: 'sha384', coordinateByteCount: 48 },
    { name: 'P-521', hash: 'sha512', coordinateByteCount: 66 },
];

export function generateKeyPair(curve) {
    return crypto.generateKeyPairSync('ec', { namedCurve: curve.name });
}

export function publicKeyToSPKIHex(publicKey) {
    return publicKey.export({ type: 'spki', format: 'der' }).toString('hex');
}

export function publicKeyFromSPKIHex(hex) {
    return crypto.createPublicKey({ key: Buffer.from(hex, 'hex'), type: 'spki', format: 'der' });
}

export function sign(curve, privateKey, message, dsaEncoding) {
    return crypto.sign(curve.hash, message, { key: privateKey, dsaEncoding });
}

/** OpenSSL's verdict. A signature it cannot parse counts as not accepted. */
export function verifies(curve, publicKey, message, signature, dsaEncoding) {
    try {
        return crypto.verify(curve.hash, message, { key: publicKey, dsaEncoding }, signature);
    } catch {
        return false;
    }
}
