// Generates the fixture in Tests/JOSEJWTEncryptedTests/Fixtures by running the counterpart
// implementation, panva/jose.
//
//     cd interop && npm ci && node generate-encrypted-fixtures.mjs
//
// Every token is produced by jose, and every verdict is jose's own. Nothing is transcribed from
// a specification. The fixture changes on every run because keys are random.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CompactEncrypt, EncryptJWT, SignJWT, base64url, compactDecrypt, exportJWK, generateKeyPair, jwtDecrypt, jwtVerify } from 'jose';
import { joseVersion } from './common.mjs';

const fixturesDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../Tests/JOSEJWTEncryptedTests/Fixtures');

function assert(condition, message) {
    if (!condition) {
        throw new Error(`fixture generation self-check failed: ${message}`);
    }
}

// A fixed "now" so that the fixture does not go stale.
const NOW = 1_800_000_000;
const currentDate = new Date(NOW * 1000);
const ISSUER = 'https://issuer.example';
const AUDIENCE = 'https://api.example';

export async function recipients() {
    const secret32 = crypto.createSecretKey(crypto.randomBytes(32));
    const wrap = crypto.createSecretKey(crypto.randomBytes(32));
    const ec = await generateKeyPair('ECDH-ES', { crv: 'P-256', extractable: true });
    const rsa = await generateKeyPair('RSA-OAEP-256', { extractable: true });
    return [
        { alg: 'dir', enc: 'A256GCM', encryptKey: secret32, decryptKey: secret32 },
        { alg: 'A256KW', enc: 'A128CBC-HS256', encryptKey: wrap, decryptKey: wrap },
        { alg: 'ECDH-ES', enc: 'A256GCM', encryptKey: ec.publicKey, decryptKey: ec.privateKey },
        { alg: 'RSA-OAEP-256', enc: 'A256CBC-HS512', encryptKey: rsa.publicKey, decryptKey: rsa.privateKey },
    ];
}

async function main() {
    const all = await recipients();

    // Encrypted JWTs: one valid token per recipient algorithm.
    const encrypted = [];
    for (const recipient of all) {
        const token = await new EncryptJWT({ scope: 'read write', level: 3 })
            .setProtectedHeader({ alg: recipient.alg, enc: recipient.enc, typ: 'JWT' })
            .setIssuer(ISSUER)
            .setSubject('user-123')
            .setAudience(AUDIENCE)
            .setIssuedAt(NOW - 10)
            .setExpirationTime(NOW + 300)
            .encrypt(recipient.encryptKey);
        const { payload } = await jwtDecrypt(token, recipient.decryptKey, { issuer: ISSUER, audience: AUDIENCE, currentDate });
        encrypted.push({ algorithm: recipient.alg, jwk: JSON.stringify(await exportJWK(recipient.decryptKey)), token, payload: JSON.stringify(payload) });
    }

    // Verdicts, all with the A256KW recipient.
    const recipient = all[1];
    const other = crypto.createSecretKey(crypto.randomBytes(32));
    const make = (adjust = (jwt) => jwt, header = { alg: recipient.alg, enc: recipient.enc, typ: 'JWT' }) =>
        adjust(new EncryptJWT({ scope: 'read' }).setProtectedHeader(header).setIssuer(ISSUER).setAudience(AUDIENCE).setExpirationTime(NOW + 60)).encrypt(recipient.encryptKey);
    const raw = (text, header) => new CompactEncrypt(Buffer.from(text, 'utf8')).setProtectedHeader({ alg: recipient.alg, enc: recipient.enc, ...header }).encrypt(recipient.encryptKey);
    const good = await make();
    const parts = good.split('.');
    const flipped = Buffer.from(base64url.decode(parts[4]));
    flipped[0] ^= 1;
    const options = { issuer: ISSUER, audience: AUDIENCE };
    const definitions = [
        ['valid (positive control)', good, options],
        ['valid, nothing checked', good, {}],
        ['wrong key', good, options, true],
        ['tag altered', [parts[0], parts[1], parts[2], parts[3], base64url.encode(flipped)].join('.'), options],
        ['expired', await make((jwt) => jwt.setExpirationTime(NOW)), options],
        ['not yet valid', await make((jwt) => jwt.setNotBefore(NOW + 10)), options],
        ['issuer mismatch', good, { ...options, issuer: 'https://other.example' }],
        ['audience mismatch', good, { ...options, audience: 'https://other.example' }],
        ['typ mismatch', good, { ...options, typ: 'at+jwt' }],
        ['typ matches', good, { ...options, typ: 'application/jwt' }],
        ['issuer replicated in the header, matching', await make((jwt) => jwt.replicateIssuerAsHeader()), options],
        ['audience replicated in the header, matching', await make((jwt) => jwt.replicateAudienceAsHeader()), options],
        ['issuer replicated in the header, different', await make((jwt) => jwt, { alg: recipient.alg, enc: recipient.enc, iss: 'https://evil.example' }), options],
        ['subject replicated in the header, but no sub claim', await make((jwt) => jwt, { alg: recipient.alg, enc: recipient.enc, sub: 'someone' }), options],
        ['plaintext is not JSON', await raw('not json', { typ: 'JWT' }), {}],
        ['plaintext is a JSON array', await raw('[]', { typ: 'JWT' }), {}],
        ['claims have a duplicate exp, the last one valid', await raw(`{"exp":${NOW - 100},"exp":${NOW + 100}}`, { typ: 'JWT' }), {}],
        ['exp is a string', await raw(`{"exp":"${NOW + 100}"}`, { typ: 'JWT' }), {}],
    ];
    const validation = [];
    for (const [name, token, opts, wrongKey] of definitions) {
        let jose;
        try {
            await jwtDecrypt(token, wrongKey ? other : recipient.decryptKey, { ...opts, currentDate });
            jose = { accepted: true };
        } catch (error) {
            jose = { accepted: false, error: `${error.code ?? error.name}: ${error.message}` };
        }
        validation.push({ name, token, options: opts, wrongKey: wrongKey ?? false, jose });
    }
    assert(validation[0].jose.accepted, 'positive control was rejected by jose');

    // Nested JWTs: signed with ES256, then encrypted with cty JWT.
    const signer = await generateKeyPair('ES256', { extractable: true });
    const stranger = await generateKeyPair('ES256', { extractable: true });
    const sign = (key, adjust = (jwt) => jwt) =>
        adjust(new SignJWT({ scope: 'read' }).setProtectedHeader({ alg: 'ES256', typ: 'JWT' }).setIssuer(ISSUER).setAudience(AUDIENCE).setExpirationTime(NOW + 60)).sign(key);
    const wrapInner = (inner, header = { cty: 'JWT' }) => raw(inner, header);
    const nestedDefinitions = [
        ['valid (positive control)', await wrapInner(await sign(signer.privateKey))],
        ['inner signed by a different key', await wrapInner(await sign(stranger.privateKey))],
        ['inner expired', await wrapInner(await sign(signer.privateKey, (jwt) => jwt.setExpirationTime(NOW)))],
        ['inner for another audience', await wrapInner(await sign(signer.privateKey, (jwt) => jwt.setAudience('https://other.example')))],
        ['inner is not a JWT', await wrapInner('not.a.jwt')],
        ['inner uses alg none', await wrapInner(`${base64url.encode('{"alg":"none"}')}.${base64url.encode(`{"iss":"${ISSUER}","aud":"${AUDIENCE}","exp":${NOW + 60}}`)}.`)],
        ['cty in lower case with application/ prefix', await wrapInner(await sign(signer.privateKey), { cty: 'application/jwt' })],
    ];
    const nested = [];
    for (const [name, token] of nestedDefinitions) {
        let jose;
        try {
            const { plaintext } = await compactDecrypt(token, recipient.decryptKey);
            await jwtVerify(Buffer.from(plaintext).toString('utf8'), signer.publicKey, { ...options, currentDate });
            jose = { accepted: true };
        } catch (error) {
            jose = { accepted: false, error: `${error.code ?? error.name}: ${error.message}` };
        }
        nested.push({ name, token, jose });
    }
    assert(nested[0].jose.accepted, 'nested positive control was rejected by jose');

    const fixture = {
        _generated: {
            notice: 'GENERATED FILE. Do not edit by hand; rerun interop/generate-encrypted-fixtures.mjs.',
            generator: 'interop/generate-encrypted-fixtures.mjs',
            description: 'Encrypted and nested JWTs from jose, with jose\'s verdicts at a fixed current time.',
            jose: joseVersion,
            node: process.version,
        },
        now: NOW,
        encrypted,
        validationJwk: JSON.stringify(await exportJWK(recipient.decryptKey)),
        validationWrongJwk: JSON.stringify(await exportJWK(other)),
        validation,
        nestedSignerJwk: JSON.stringify(await exportJWK(signer.publicKey)),
        nested,
    };
    fs.writeFileSync(path.join(fixturesDirectory, 'encrypted.json'), JSON.stringify(fixture, null, 2) + '\n');
    console.log('wrote encrypted.json');
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
    await main();
}
