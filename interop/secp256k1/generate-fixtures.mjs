// Generates the fixtures in Tests/JOSESecp256k1Tests/Fixtures by running the counterpart: Node's
// crypto module (OpenSSL) for keys, signatures and verdicts, and panva/jose for thumbprints.
//
//     cd interop && npm ci && node secp256k1/generate-fixtures.mjs
//
// Every expected value is produced by the counterpart. Nothing is transcribed from a
// specification. The fixtures change on every run because keys and signatures are random.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { base64url, calculateJwkThumbprint } from 'jose';
import {
    ORDER, compact, exportJwk, flipLastBit, generateKeyPair, isLowS, joseVersion, otherForm, sign, signingInput, verifies,
    withR, withS,
} from './common.mjs';

const fixturesDirectory = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '../../Tests/JOSESecp256k1Tests/Fixtures',
);

function write(name, description, body) {
    const fixture = {
        _generated: {
            notice: 'GENERATED FILE. Do not edit by hand; rerun interop/secp256k1/generate-fixtures.mjs.',
            generator: 'interop/secp256k1/generate-fixtures.mjs',
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
    for (let i = 0; i < 4; i++) {
        const { publicKey, privateKey } = generateKeyPair();
        const publicJwk = exportJwk(publicKey);
        const thumbprints = {};
        for (const hash of HASHES) {
            thumbprints[hash] = await calculateJwkThumbprint(publicJwk, hash);
        }
        keys.push({
            publicJwk: JSON.stringify(publicJwk),
            privateJwk: JSON.stringify(exportJwk(privateKey)),
            x963: publicKey.export({ format: 'der', type: 'spki' }).subarray(-65).toString('hex'),
            thumbprints,
        });
    }
    write('keys.json', 'secp256k1 key pairs made by OpenSSL, as JWKs, with their jose thumbprints.', { keys });
}

/**
 * ES256K JWSs signed by OpenSSL, with OpenSSL's verdict on each. Every key contributes a signature
 * in both S forms, and variants that must fail.
 */
function signaturesFixture() {
    const cases = [];
    let highS = 0;
    for (let i = 0; i < 6; i++) {
        const { publicKey, privateKey } = generateKeyPair();
        const other = generateKeyPair().publicKey;
        const jwk = JSON.stringify(exportJwk(publicKey));
        const otherJwk = JSON.stringify(exportJwk(other));
        const payload = crypto.randomBytes(1 + i * 20);
        const input = signingInput({ alg: 'ES256K', kid: `key-${i}` }, payload);
        const signature = sign(privateKey, input);
        const low = isLowS(signature) ? signature : otherForm(signature);
        const high = otherForm(low);
        highS += isLowS(signature) ? 0 : 1;

        const variants = [
            { name: 'low S', signature: low },
            { name: 'high S', signature: high },
            { name: 's is the order', signature: withS(low, ORDER) },
            { name: 's is the order plus one', signature: withS(low, ORDER + 1n) },
            { name: 's is 2^256 - 1', signature: withS(low, (1n << 256n) - 1n) },
            { name: 's is zero', signature: withS(low, 0n) },
            { name: 'r is zero', signature: withR(low, 0n) },
            { name: 'r is the order', signature: withR(low, ORDER) },
            { name: 'last bit flipped', signature: flipLastBit(low) },
            { name: 'last bit of high S flipped', signature: flipLastBit(high) },
            { name: 'verified with another key', signature: low, key: other, jwk: otherJwk },
            { name: 'high S verified with another key', signature: high, key: other, jwk: otherJwk },
            { name: 'payload altered', signature: low, input: signingInput({ alg: 'ES256K', kid: `key-${i}` }, Buffer.from('x')) },
        ];
        for (const variant of variants) {
            const variantInput = variant.input ?? input;
            const accepted = verifies(variant.key ?? publicKey, variantInput, variant.signature);
            cases.push({
                name: variant.name,
                jwk: variant.jwk ?? jwk,
                token: compact(variantInput, variant.signature),
                payload: Buffer.from(base64url.decode(variantInput.split('.')[1])).toString('hex'),
                openssl: { accepted },
            });
        }
    }
    assert(cases.some((c) => c.name === 'high S' && c.openssl.accepted), 'OpenSSL accepts high S');
    assert(cases.filter((c) => c.openssl.accepted).every((c) => c.name === 'low S' || c.name === 'high S'), 'only the two forms verify');
    write('signatures.json', `ES256K JWSs signed by OpenSSL (${highS} of 6 originally high S), with OpenSSL's verdict on each.`, { cases });
}

function opensslImport(jwk, type) {
    try {
        const key = type === 'public' ? crypto.createPublicKey({ key: jwk, format: 'jwk' }) : crypto.createPrivateKey({ key: jwk, format: 'jwk' });
        return { accepted: true, importedAs: key.type };
    } catch (error) {
        return { accepted: false, error: `${error.code ?? error.name}: ${error.message}` };
    }
}

/** secp256k1 JWK documents, well-formed and not, with what OpenSSL makes of each. */
function parsingFixture() {
    const first = exportJwk(generateKeyPair().publicKey);
    const second = generateKeyPair();
    const secondPublic = exportJwk(second.publicKey);
    const secondPrivate = exportJwk(second.privateKey);
    const third = exportJwk(generateKeyPair().privateKey);
    const without = (jwk, member) => {
        const copy = { ...jwk };
        delete copy[member];
        return copy;
    };
    const xBytes = Buffer.from(base64url.decode(first.x));

    const publicCandidates = {
        'valid (positive control)': first,
        'valid with kid, use and alg': { ...first, kid: 'key-1', use: 'sig', alg: 'ES256K' },
        'x missing': without(first, 'x'),
        'y missing': without(first, 'y'),
        'x is a number': { ...first, x: 12345 },
        'x is not base64url (standard alphabet)': { ...first, x: first.x.slice(0, -2) + '+/' },
        'x is padded': { ...first, x: first.x + '=' },
        'x has one byte too few': { ...first, x: base64url.encode(xBytes.subarray(1)) },
        'x has one byte too many': { ...first, x: base64url.encode(Buffer.concat([Buffer.from([0]), xBytes])) },
        'x is empty': { ...first, x: '' },
        'y from a different key (point not on curve)': { ...first, y: secondPublic.y },
        'x and y swapped (point not on curve)': { ...first, x: first.y, y: first.x },
        'private member d present': secondPrivate,
    };
    const privateCandidates = {
        'valid (positive control)': secondPrivate,
        'valid with kid, use and alg': { ...secondPrivate, kid: 'key-2', use: 'sig', alg: 'ES256K' },
        'd missing': secondPublic,
        'd from a different key': { ...secondPrivate, d: third.d },
        'd is zero': { ...secondPrivate, d: base64url.encode(Buffer.alloc(32)) },
        'd is the order': { ...secondPrivate, d: base64url.encode(Buffer.from(ORDER.toString(16), 'hex')) },
        'd has one byte too few': { ...secondPrivate, d: base64url.encode(Buffer.from(base64url.decode(secondPrivate.d)).subarray(1)) },
    };

    const cases = [];
    for (const [name, jwk] of Object.entries(publicCandidates)) {
        cases.push({ type: 'public', name, json: JSON.stringify(jwk), openssl: opensslImport(jwk, 'public') });
    }
    for (const [name, jwk] of Object.entries(privateCandidates)) {
        cases.push({ type: 'private', name, json: JSON.stringify(jwk), openssl: opensslImport(jwk, 'private') });
    }
    assert(cases[0].openssl.accepted, 'the positive control imports');
    write('jwk-parsing.json', 'secp256k1 JWK documents, well-formed and not, with what OpenSSL makes of each.', { cases });
}

await keysFixture();
signaturesFixture();
parsingFixture();
