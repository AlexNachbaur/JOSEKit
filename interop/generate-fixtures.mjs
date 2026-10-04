// Generates the fixtures in Tests/JOSEJWKTests/Fixtures by running the counterpart
// implementation: panva/jose and Node's WebCrypto (OpenSSL).
//
//     cd interop && npm ci && node generate-fixtures.mjs
//
// Every expected value is produced by the counterpart. Nothing is transcribed from a
// specification. The fixtures change on every run because keys and signatures are random.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { base64url, calculateJwkThumbprint, calculateJwkThumbprintUri, exportJWK, generateKeyPair, importJWK } from 'jose';
import { ASYMMETRIC, HMAC, flipLastBit, hmac, joseVersion, sign, verifies } from './common.mjs';

const fixturesDirectory = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '../Tests/JOSEJWKTests/Fixtures',
);

function write(name, description, body) {
    const fixture = {
        _generated: {
            notice: 'GENERATED FILE. Do not edit by hand; rerun interop/generate-fixtures.mjs.',
            generator: 'interop/generate-fixtures.mjs',
            description,
            jose: joseVersion,
            node: process.version,
            openssl: process.versions.openssl,
        },
        ...body,
    };
    fs.writeFileSync(path.join(fixturesDirectory, name), JSON.stringify(fixture, null, 2) + '\n');
    console.log(`wrote ${name}`);
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(`fixture generation self-check failed: ${message}`);
    }
}

const HASHES = ['sha256', 'sha384', 'sha512'];

async function keysFixture() {
    const keys = [];
    for (const kind of ASYMMETRIC) {
        for (let i = 0; i < 4; i++) {
            const { publicKey, privateKey } = await generateKeyPair(kind.joseAlg, { extractable: true });
            const publicJwk = await exportJWK(publicKey);
            const privateJwk = await exportJWK(privateKey);

            const thumbprints = {};
            const thumbprintUris = {};
            for (const hash of HASHES) {
                thumbprints[hash] = await calculateJwkThumbprint(publicJwk, hash);
                thumbprintUris[hash] = await calculateJwkThumbprintUri(publicJwk, hash);
            }

            const signatures = [];
            for (let j = 0; j < 3; j++) {
                const message = crypto.randomBytes(j * 40);
                const signature = await sign(kind, privateKey, message);
                assert(await verifies(kind, publicKey, message, signature), 'counterpart rejected its own signature');
                const tampered = flipLastBit(signature);
                assert(!(await verifies(kind, publicKey, message, tampered)), 'counterpart accepted a tampered signature');
                signatures.push({
                    message: message.toString('hex'),
                    signature: signature.toString('hex'),
                    tamperedSignature: tampered.toString('hex'),
                });
            }

            keys.push({
                curve: kind.name,
                algorithms: kind.algs,
                publicJwk,
                privateJwk,
                // For EC keys this is the uncompressed X9.63 point; for Ed25519, the 32-byte key.
                rawPublicKey: Buffer.from(await crypto.subtle.exportKey('raw', publicKey)).toString('hex'),
                thumbprints,
                thumbprintUris,
                signatures,
            });
        }
    }

    const hmacs = [];
    for (const spec of HMAC) {
        for (const keyLength of [spec.byteCount, spec.byteCount + 17, 128]) {
            const key = crypto.randomBytes(keyLength);
            const message = crypto.randomBytes(50);
            const tag = hmac(spec, key, message);
            hmacs.push({
                algorithm: spec.alg,
                jwk: await exportJWK(crypto.createSecretKey(key)),
                key: key.toString('hex'),
                message: message.toString('hex'),
                tag: tag.toString('hex'),
                tamperedTag: flipLastBit(tag).toString('hex'),
            });
        }
    }

    write('keys.json', 'Keys exported by jose as JWKs, with thumbprints from jose and signatures from WebCrypto.', {
        keys,
        hmacs,
    });
}

async function invalidJwkFixture() {
    const cases = [];
    for (const kind of ASYMMETRIC) {
        const first = await exportJWK((await generateKeyPair(kind.joseAlg, { extractable: true })).publicKey);
        const secondPair = await generateKeyPair(kind.joseAlg, { extractable: true });
        const second = await exportJWK(secondPair.publicKey);
        const secondPrivate = await exportJWK(secondPair.privateKey);
        const without = (jwk, member) => {
            const copy = { ...jwk };
            delete copy[member];
            return copy;
        };
        const xBytes = Buffer.from(base64url.decode(first.x));

        const candidates = {
            'valid (positive control)': first,
            'valid with kid, use and alg': { ...first, kid: 'key-1', use: 'sig', alg: kind.algs[0] },
            'kty missing': without(first, 'kty'),
            'crv missing': without(first, 'crv'),
            'x missing': without(first, 'x'),
            'x is a number': { ...first, x: 12345 },
            'x is not base64url (standard alphabet)': { ...first, x: first.x.slice(0, -2) + '+/' },
            'x is padded': { ...first, x: first.x + '=' },
            'x has one byte too few': { ...first, x: base64url.encode(xBytes.subarray(1)) },
            'x has one byte too many': { ...first, x: base64url.encode(Buffer.concat([Buffer.from([0]), xBytes])) },
            'x is empty': { ...first, x: '' },
            'kty is oct': { kty: 'oct', k: base64url.encode(crypto.randomBytes(32)) },
            'kty is unknown': { ...first, kty: 'XYZ' },
            'crv is unknown': { ...first, crv: 'P-999' },
            'private member d present': secondPrivate,
        };
        if (first.kty === 'EC') {
            Object.assign(candidates, {
                'y missing': without(first, 'y'),
                'y from a different key (point not on curve)': { ...first, y: second.y },
                'x and y swapped (point not on curve)': { ...first, x: first.y, y: first.x },
                'crv names a different curve': { ...first, crv: kind.name === 'P-256' ? 'P-384' : 'P-256' },
            });
        }

        for (const [name, jwk] of Object.entries(candidates)) {
            let jose;
            try {
                const imported = await importJWK(jwk, kind.joseAlg);
                jose = { accepted: true, importedAs: imported.type ?? 'secret' };
            } catch (error) {
                jose = { accepted: false, error: `${error.name}: ${error.message}` };
            }
            cases.push({ curve: kind.name, name, json: JSON.stringify(jwk), jose });
        }
    }
    write('jwk-parsing.json', 'JWK documents, well-formed and not, with what jose importJWK does with each.', { cases });
}

await keysFixture();
await invalidJwkFixture();
