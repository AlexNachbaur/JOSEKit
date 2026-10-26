// Generates Tests/JOSEJWKTests/Fixtures/pem.json with Node's crypto (OpenSSL): keys of every
// type JOSEJWK reads from PEM, exported in every PEM format OpenSSL writes for them, each with
// the same key as a JWK for the expected values.
//
//     cd interop && npm ci && node jwk/generate-pem-fixtures.mjs
//
// Every expected value is produced by OpenSSL. Nothing is transcribed from a specification.
// The fixture changes on every run because the keys are random.

import crypto from 'node:crypto';
import { fixtureWriter } from '../shared/fixtures.mjs';

const write = fixtureWriter(import.meta.url, 'JOSEJWKTests');

function pem(key, type) {
    return key.export({ type, format: 'pem' });
}

/// One key pair, in each format its type can be written in.
function entry(label, kind, options, formats) {
    const { publicKey, privateKey } = crypto.generateKeyPairSync(kind, options);
    const encodings = [];
    for (const format of formats.public) {
        encodings.push({ label: `${label} ${format} public`, pem: pem(publicKey, format), isPrivate: false });
    }
    for (const format of formats.private) {
        encodings.push({ label: `${label} ${format} private`, pem: pem(privateKey, format), isPrivate: true });
    }
    return {
        label,
        publicJwk: publicKey.export({ format: 'jwk' }),
        privateJwk: privateKey.export({ format: 'jwk' }),
        encodings,
    };
}

const keys = [
    entry('RSA 2048', 'rsa', { modulusLength: 2048 }, { public: ['spki', 'pkcs1'], private: ['pkcs8', 'pkcs1'] }),
    entry('RSA 3072', 'rsa', { modulusLength: 3072 }, { public: ['spki', 'pkcs1'], private: ['pkcs8', 'pkcs1'] }),
    entry('P-256', 'ec', { namedCurve: 'P-256' }, { public: ['spki'], private: ['pkcs8', 'sec1'] }),
    entry('P-384', 'ec', { namedCurve: 'P-384' }, { public: ['spki'], private: ['pkcs8', 'sec1'] }),
    entry('P-521', 'ec', { namedCurve: 'P-521' }, { public: ['spki'], private: ['pkcs8', 'sec1'] }),
    entry('Ed25519', 'ed25519', {}, { public: ['spki'], private: ['pkcs8'] }),
    entry('X25519', 'x25519', {}, { public: ['spki'], private: ['pkcs8'] }),
];

// PEMs this package must refuse, with the reason recorded for the test.
const refused = [];
{
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ec', { namedCurve: 'brainpoolP256r1' });
    refused.push({ label: 'brainpoolP256r1 spki (curve not supported)', pem: pem(publicKey, 'spki'), isPrivate: false, reason: 'unsupportedKeyAlgorithm' });
    refused.push({ label: 'brainpoolP256r1 pkcs8 (curve not supported)', pem: pem(privateKey, 'pkcs8'), isPrivate: true, reason: 'unsupportedKeyAlgorithm' });
}
{
    const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
    refused.push({
        label: 'encrypted pkcs8',
        pem: privateKey.export({ type: 'pkcs8', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'secret' }),
        isPrivate: true,
        reason: 'wrongPEMType',
    });
    refused.push({
        label: 'legacy encrypted pkcs1',
        pem: privateKey.export({ type: 'pkcs1', format: 'pem', cipher: 'aes-256-cbc', passphrase: 'secret' }),
        isPrivate: true,
        reason: 'invalidPEM',
    });
}
{
    const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 });
    refused.push({ label: 'RSA 1024 spki (too small)', pem: pem(publicKey, 'spki'), isPrivate: false, reason: 'rsaKeyTooSmall' });
    refused.push({ label: 'RSA 1024 pkcs8 (too small)', pem: pem(privateKey, 'pkcs8'), isPrivate: true, reason: 'rsaKeyTooSmall' });
}
{
    const { publicKey, privateKey } = crypto.generateKeyPairSync('ed448');
    refused.push({ label: 'Ed448 spki (not supported)', pem: pem(publicKey, 'spki'), isPrivate: false, reason: 'unsupportedKeyAlgorithm' });
    refused.push({ label: 'Ed448 pkcs8 (not supported)', pem: pem(privateKey, 'pkcs8'), isPrivate: true, reason: 'unsupportedKeyAlgorithm' });
}

write(
    'pem.json',
    'Keys exported by OpenSSL as PEM in each format, with the same keys as JWKs, and PEMs to refuse.',
    { keys, refused },
);
