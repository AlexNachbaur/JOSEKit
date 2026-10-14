// Generates the fixtures in Tests/JOSEJWTTests/Fixtures by running the counterpart
// implementation, panva/jose.
//
//     cd interop && npm ci && node generate-fixtures.mjs
//
// Every token is produced by jose, and every verdict is jose's own. Nothing is transcribed from
// a specification. The fixtures change on every run because keys and signatures are random.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CompactSign, FlattenedSign, SignJWT, exportJWK, generateKeyPair, jwtVerify } from 'jose';
import { HMAC, joseVersion } from './common.mjs';

const fixturesDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../Tests/JOSEJWTTests/Fixtures');

function write(name, description, body) {
    const fixture = {
        _generated: {
            notice: 'GENERATED FILE. Do not edit by hand; rerun interop/jwt/generate-fixtures.mjs.',
            generator: 'interop/jwt/generate-fixtures.mjs',
            description,
            jose: joseVersion,
            node: process.version,
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

// A fixed "now" so that the fixtures do not go stale. All time-dependent verdicts are taken with
// jose's clock set to this instant.
const NOW = 1_800_000_000;

async function setups() {
    const result = [];
    for (const [alg, joseAlg] of [['ES256', 'ES256'], ['ES384', 'ES384'], ['Ed25519', 'Ed25519'], ['EdDSA', 'Ed25519'], ['RS256', 'RS256'], ['PS256', 'PS256']]) {
        const { publicKey, privateKey } = await generateKeyPair(joseAlg, { extractable: true });
        result.push({ alg, signKey: privateKey, verifyKey: publicKey, jwk: await exportJWK(publicKey) });
    }
    const spec = HMAC[0];
    const secret = crypto.createSecretKey(crypto.randomBytes(spec.byteCount));
    result.push({ alg: spec.alg, signKey: secret, verifyKey: secret, jwk: await exportJWK(secret) });
    return result;
}

async function validFixture(all) {
    const tokens = [];
    for (const [index, setup] of all.entries()) {
        const claims = {
            scope: 'read write',
            level: 3,
            nested: { flag: true, list: [1, 'two'] },
            'https://example.com/claim': 'namespaced',
        };
        const audience = index % 2 === 0 ? 'https://api.example' : ['https://api.example', 'https://other.example'];
        const token = await new SignJWT(claims)
            .setProtectedHeader({ alg: setup.alg, typ: 'JWT', kid: `${setup.alg}-key` })
            .setIssuer('https://issuer.example')
            .setSubject('user-123')
            .setAudience(audience)
            .setIssuedAt(NOW - 10)
            .setNotBefore(NOW - 10)
            .setExpirationTime(NOW + 300)
            .setJti(`id-${index}`)
            .sign(setup.signKey);
        const { payload } = await jwtVerify(token, setup.verifyKey, {
            issuer: 'https://issuer.example',
            audience: 'https://api.example',
            currentDate: new Date(NOW * 1000),
        });
        tokens.push({ algorithm: setup.alg, jwk: JSON.stringify(setup.jwk), token, payload: JSON.stringify(payload), audience: [audience].flat() });
    }
    write('valid.json', 'JWTs signed by jose with SignJWT, with the claims jose reads back from them.', { now: NOW, tokens });
}

async function validationFixture(all) {
    const setup = all.find((candidate) => candidate.alg === 'ES256');

    // Signs an exact payload text with a given header, so that a case can present claims that
    // SignJWT would refuse to write.
    const signRaw = (payloadText, header = { alg: 'ES256', typ: 'JWT' }) =>
        new CompactSign(Buffer.from(payloadText, 'utf8')).setProtectedHeader(header).sign(setup.signKey);
    const signClaims = (claims, header) => signRaw(JSON.stringify(claims), header);

    const base = { iss: 'https://issuer.example', sub: 'user', aud: 'https://api.example', exp: NOW + 60 };
    const noOptions = {};
    const definitions = [
        ['valid, nothing checked (positive control)', base, noOptions],
        ['valid, issuer and audience checked', base, { issuer: 'https://issuer.example', audience: 'https://api.example' }],

        ['exp one second ahead', { ...base, exp: NOW + 1 }, noOptions],
        ['exp equal to now', { ...base, exp: NOW }, noOptions],
        ['exp one second ago', { ...base, exp: NOW - 1 }, noOptions],
        ['exp half a second ahead', { ...base, exp: NOW + 0.5 }, noOptions],
        ['exp five seconds ago, tolerance five', { ...base, exp: NOW - 5 }, { clockTolerance: 5 }],
        ['exp five seconds ago, tolerance six', { ...base, exp: NOW - 5 }, { clockTolerance: 6 }],
        ['exp absent', { iss: base.iss, aud: base.aud }, noOptions],
        ['exp is a numeric string', { ...base, exp: String(NOW + 60) }, noOptions],
        ['exp is null', { ...base, exp: null }, noOptions],
        ['exp is a boolean', { ...base, exp: true }, noOptions],

        ['nbf equal to now', { ...base, nbf: NOW }, noOptions],
        ['nbf one second ahead', { ...base, nbf: NOW + 1 }, noOptions],
        ['nbf one second ago', { ...base, nbf: NOW - 1 }, noOptions],
        ['nbf five seconds ahead, tolerance five', { ...base, nbf: NOW + 5 }, { clockTolerance: 5 }],
        ['nbf five seconds ahead, tolerance four', { ...base, nbf: NOW + 5 }, { clockTolerance: 4 }],
        ['nbf is a string', { ...base, nbf: 'soon' }, noOptions],
        ['iat in the future', { ...base, iat: NOW + 1000 }, noOptions],
        ['iat is a string', { ...base, iat: 'then' }, noOptions],

        ['issuer mismatch', base, { issuer: 'https://other.example' }],
        ['issuer differs only in case', base, { issuer: 'https://ISSUER.example' }],
        ['issuer absent but expected', { aud: base.aud, exp: base.exp }, { issuer: 'https://issuer.example' }],
        ['issuer one of several accepted', base, { issuer: ['https://a.example', 'https://issuer.example'] }],
        ['issuer none of several accepted', base, { issuer: ['https://a.example', 'https://b.example'] }],
        ['iss is a number', { ...base, iss: 7 }, noOptions],
        ['sub is a number', { ...base, sub: 7 }, noOptions],
        ['jti is a number', { ...base, jti: 7 }, noOptions],

        ['audience mismatch', base, { audience: 'https://other.example' }],
        ['audience absent but expected', { iss: base.iss, exp: base.exp }, { audience: 'https://api.example' }],
        ['audience array contains expected', { ...base, aud: ['https://x.example', 'https://api.example'] }, { audience: 'https://api.example' }],
        ['audience array lacks expected', { ...base, aud: ['https://x.example', 'https://y.example'] }, { audience: 'https://api.example' }],
        ['audience one of several accepted', base, { audience: ['https://a.example', 'https://api.example'] }],
        ['audience array is empty', { ...base, aud: [] }, { audience: 'https://api.example' }],
        ['aud is a number', { ...base, aud: 7 }, noOptions],
        ['aud array has a number', { ...base, aud: ['https://api.example', 7] }, noOptions],

        ['typ matches exactly', base, { typ: 'JWT' }],
        ['typ matches ignoring case', base, { typ: 'jwt' }],
        ['typ matches with application/ prefix', base, { typ: 'application/jwt' }],
        ['typ mismatch', base, { typ: 'at+jwt' }],
        ['typ absent but expected', base, { typ: 'JWT' }, { alg: 'ES256' }],
        ['typ at+jwt expected and present', base, { typ: 'at+jwt' }, { alg: 'ES256', typ: 'application/at+jwt' }],
    ];

    const cases = [];
    for (const [name, claims, options, header] of definitions) {
        cases.push({ name, token: await signClaims(claims, header), options });
    }
    const rawCases = [
        ['claims are a JSON array', '["iss"]'],
        ['claims are a JSON string', '"claims"'],
        ['claims are not JSON', 'not json'],
        ['claims are empty', ''],
        ['claims have a duplicate exp, the last one valid', `{"exp":${NOW - 100},"exp":${NOW + 100}}`],
        ['claims have a duplicate exp, the last one expired', `{"exp":${NOW + 100},"exp":${NOW - 100}}`],
        ['claims have whitespace and unusual member order', `{ "exp" : ${NOW + 60},\n  "iss":"https://issuer.example" }`],
    ];
    for (const [name, text] of rawCases) {
        cases.push({ name, token: await signRaw(text), options: noOptions });
    }
    {
        // jose only writes b64:false through the flattened form; the compact form of the same
        // JWS is its three parts joined, with the payload text unencoded in the middle.
        const text = '{"exp":9999999999}';
        const flattened = await new FlattenedSign(Buffer.from(text, 'utf8'))
            .setProtectedHeader({ alg: 'ES256', b64: false, crit: ['b64'] })
            .sign(setup.signKey);
        cases.push({
            name: 'unencoded payload (b64 false)',
            token: `${flattened.protected}.${text}.${flattened.signature}`,
            options: noOptions,
        });
    }

    for (const testCase of cases) {
        try {
            await jwtVerify(testCase.token, setup.verifyKey, { ...testCase.options, currentDate: new Date(NOW * 1000) });
            testCase.jose = { accepted: true };
        } catch (error) {
            testCase.jose = { accepted: false, error: `${error.code ?? error.name}: ${error.message}`, claim: error.claim ?? null, reason: error.reason ?? null };
        }
    }
    assert(cases[0].jose.accepted, 'positive control was rejected by jose');

    write('validation.json', 'JWTs with jose jwtVerify\'s verdict under the stated options, at a fixed current time.', {
        now: NOW,
        jwk: JSON.stringify(setup.jwk),
        cases,
    });
}

const all = await setups();
await validFixture(all);
await validationFixture(all);
