// Generates the fixtures in Tests/JOSEJWKTests/Fixtures by running the counterpart
// implementation: panva/jose and Node's WebCrypto (OpenSSL).
//
//     cd interop && npm ci && node jwk/generate-fixtures.mjs
//
// Every expected value is produced by the counterpart. Nothing is transcribed from a
// specification. The fixtures change on every run because keys and signatures are random.

import crypto from 'node:crypto';
import { base64url, calculateJwkThumbprint, calculateJwkThumbprintUri, exportJWK, generateKeyPair, importJWK } from 'jose';
import { ASYMMETRIC, HMAC, RSA, hmac, rsaSign, rsaVerifies, sign, verifies } from '../shared/algorithms.mjs';
import { assert, fixtureWriter, flipLastBit } from '../shared/fixtures.mjs';

const write = fixtureWriter(import.meta.url, 'JOSEJWKTests');

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

    const rsaKeys = [];
    for (const modulusLength of [2048, 2048, 3072, 4096]) {
        const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength });
        const publicJwk = await exportJWK(publicKey);
        const privateJwk = await exportJWK(privateKey);
        const thumbprints = {};
        const thumbprintUris = {};
        for (const hash of HASHES) {
            thumbprints[hash] = await calculateJwkThumbprint(publicJwk, hash);
            thumbprintUris[hash] = await calculateJwkThumbprintUri(publicJwk, hash);
        }
        const signatures = [];
        for (const spec of RSA) {
            const message = crypto.randomBytes(60);
            const signature = rsaSign(spec, privateKey, message);
            assert(rsaVerifies(spec, publicKey, message, signature), 'counterpart rejected its own RSA signature');
            const tampered = flipLastBit(signature);
            assert(!rsaVerifies(spec, publicKey, message, tampered), 'counterpart accepted a tampered RSA signature');
            const entry = {
                algorithm: spec.alg,
                message: message.toString('hex'),
                signature: signature.toString('hex'),
                tamperedSignature: tampered.toString('hex'),
            };
            if (spec.alg.startsWith('PS')) {
                // A genuine PSS signature by the same key, but with a salt that is not the digest
                // length. RFC 7518 §3.5 fixes the salt length, and the counterpart refuses this.
                const otherSalt = crypto.sign(spec.hash, message, { key: privateKey, ...spec.options, saltLength: 20 });
                assert(!rsaVerifies(spec, publicKey, message, otherSalt), 'counterpart accepted a non-standard salt length');
                entry.nonStandardSaltSignature = otherSalt.toString('hex');
            }
            signatures.push(entry);
        }
        // RSAES-OAEP ciphertexts made by OpenSSL, for this package to decrypt.
        const oaep = [];
        for (const hash of ['sha1', 'sha256']) {
            for (const length of [16, 32, 64]) {
                const plaintext = crypto.randomBytes(length);
                const ciphertext = crypto.publicEncrypt({ key: publicKey, padding: crypto.constants.RSA_PKCS1_OAEP_PADDING, oaepHash: hash }, plaintext);
                oaep.push({ hash, plaintext: plaintext.toString('hex'), ciphertext: ciphertext.toString('hex') });
            }
        }
        rsaKeys.push({
            oaep,
            bitCount: modulusLength,
            publicJwk,
            privateJwk,
            publicPkcs1: publicKey.export({ type: 'pkcs1', format: 'der' }).toString('hex'),
            privatePkcs1: privateKey.export({ type: 'pkcs1', format: 'der' }).toString('hex'),
            thumbprints,
            thumbprintUris,
            signatures,
        });
    }

    // ECDH. The shared secret is computed by OpenSSL from one party's private key and the
    // other's public key; this package must derive the same bytes from the same two JWKs.
    const agreements = [];
    for (const curve of ['P-256', 'P-384', 'P-521', 'X25519']) {
        for (let i = 0; i < 4; i++) {
            const generate = () =>
                curve === 'X25519' ? crypto.generateKeyPairSync('x25519') : crypto.generateKeyPairSync('ec', { namedCurve: curve });
            const ours = generate();
            const theirs = generate();
            const sharedSecret = crypto.diffieHellman({ privateKey: ours.privateKey, publicKey: theirs.publicKey });
            const reverse = crypto.diffieHellman({ privateKey: theirs.privateKey, publicKey: ours.publicKey });
            assert(sharedSecret.equals(reverse), 'ECDH is not symmetric');
            const publicJwk = await exportJWK(theirs.publicKey);
            agreements.push({
                curve,
                privateJwk: await exportJWK(ours.privateKey),
                publicJwk,
                publicThumbprint: await calculateJwkThumbprint(publicJwk, 'sha256'),
                sharedSecret: sharedSecret.toString('hex'),
            });
        }
    }

    write('keys.json', 'Keys exported by jose as JWKs, with thumbprints from jose and signatures from WebCrypto.', {
        keys,
        hmacs,
        rsaKeys,
        agreements,
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
    // RSA
    {
        const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const first = await exportJWK(pair.publicKey);
        const privateJwk = await exportJWK(pair.privateKey);
        const small = await exportJWK(crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey);
        const without = (jwk, member) => {
            const copy = { ...jwk };
            delete copy[member];
            return copy;
        };
        const nBytes = Buffer.from(base64url.decode(first.n));
        const candidates = {
            'valid (positive control)': first,
            'valid with kid, use and alg': { ...first, kid: 'rsa-1', use: 'sig', alg: 'RS256' },
            'n missing': without(first, 'n'),
            'e missing': without(first, 'e'),
            'n is a number': { ...first, n: 12345 },
            'n is not base64url (standard alphabet)': { ...first, n: first.n.slice(0, -2) + '+/' },
            'n is empty': { ...first, n: '' },
            '1024-bit key': small,
            'n has a leading zero byte': { ...first, n: base64url.encode(Buffer.concat([Buffer.from([0]), nBytes])) },
            'e has a leading zero byte': { ...first, e: 'AAEAAQ' },
            'e is even': { ...first, e: 'AQAA' },
            'e is 1': { ...first, e: 'AQ' },
            'n is even': { ...first, n: base64url.encode(Buffer.concat([nBytes.subarray(0, nBytes.length - 1), Buffer.from([nBytes[nBytes.length - 1] & 0xfe])])) },
            'private member d present': privateJwk,
        };
        for (const [name, jwk] of Object.entries(candidates)) {
            let jose;
            try {
                const imported = await importJWK(jwk, 'RS256');
                jose = { accepted: true, importedAs: imported.type ?? 'secret' };
            } catch (error) {
                jose = { accepted: false, error: `${error.name}: ${error.message}` };
            }
            cases.push({ curve: 'RSA', name, json: JSON.stringify(jwk), jose });
        }
    }

    write('jwk-parsing.json', 'JWK documents, well-formed and not, with what jose importJWK does with each.', { cases });
}

await keysFixture();
await invalidJwkFixture();
