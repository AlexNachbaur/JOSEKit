// Shared by the fixture generator and the closed-loop check.

import crypto from 'node:crypto';
import { createRequire } from 'node:module';
import { exportJWK, generateKeyPair } from 'jose';

const require = createRequire(import.meta.url);
export const joseVersion = require('jose/package.json').version;

export const ENCRYPTIONS = [
    { enc: 'A128GCM', keyByteCount: 16 },
    { enc: 'A192GCM', keyByteCount: 24 },
    { enc: 'A256GCM', keyByteCount: 32 },
    { enc: 'A128CBC-HS256', keyByteCount: 32 },
    { enc: 'A192CBC-HS384', keyByteCount: 48 },
    { enc: 'A256CBC-HS512', keyByteCount: 64 },
];

const SYMMETRIC = { A128KW: 16, A192KW: 24, A256KW: 32, A128GCMKW: 16, A192GCMKW: 24, A256GCMKW: 32 };
const ECDH = ['ECDH-ES', 'ECDH-ES+A128KW', 'ECDH-ES+A192KW', 'ECDH-ES+A256KW'];
const CURVES = ['P-256', 'P-384', 'P-521', 'X25519'];

/**
 * Every key management configuration: an algorithm, a label that also says which curve, and a
 * function that makes the keys for a given `enc`. `decryptJwk` is what the Swift side is given.
 */
export function keyManagementSetups() {
    const setups = [];
    setups.push({
        alg: 'dir',
        label: 'dir',
        async keys(encryption) {
            const secret = crypto.createSecretKey(crypto.randomBytes(encryption.keyByteCount));
            return { encryptKey: secret, decryptKey: secret, decryptJwk: await exportJWK(secret), encryptJwk: await exportJWK(secret) };
        },
    });
    for (const [alg, byteCount] of Object.entries(SYMMETRIC)) {
        setups.push({
            alg,
            label: alg,
            async keys() {
                const secret = crypto.createSecretKey(crypto.randomBytes(byteCount));
                return { encryptKey: secret, decryptKey: secret, decryptJwk: await exportJWK(secret), encryptJwk: await exportJWK(secret) };
            },
        });
    }
    for (const alg of ECDH) {
        for (const crv of CURVES) {
            setups.push({
                alg,
                label: `${alg} ${crv}`,
                curve: crv,
                async keys() {
                    const pair = await generateKeyPair(alg, { crv, extractable: true });
                    return { encryptKey: pair.publicKey, decryptKey: pair.privateKey, decryptJwk: await exportJWK(pair.privateKey), encryptJwk: await exportJWK(pair.publicKey) };
                },
            });
        }
    }
    for (const alg of ['RSA-OAEP', 'RSA-OAEP-256']) {
        setups.push({
            alg,
            label: alg,
            async keys() {
                const pair = await generateKeyPair(alg, { extractable: true });
                return { encryptKey: pair.publicKey, decryptKey: pair.privateKey, decryptJwk: await exportJWK(pair.privateKey), encryptJwk: await exportJWK(pair.publicKey) };
            },
        });
    }
    return setups;
}

export function flipLastBit(buffer) {
    const copy = Buffer.from(buffer);
    copy[copy.length - 1] ^= 0x01;
    return copy;
}
