// Closed-loop interoperability check. The counterpart sets a challenge, the Swift package
// answers it, and the counterpart judges the answers.
//
//     node closed-loop.mjs challenge <challenge.json>
//     swift run jose-jwt-interop < challenge.json > response.json
//     node closed-loop.mjs verify <challenge.json> <response.json>
//
// `scripts/interop.sh` runs all three. `verify` exits non-zero on any disagreement.

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { SignJWT, base64url, exportJWK, generateKeyPair, importJWK, jwtVerify } from 'jose';

const ALGORITHMS = ['ES256', 'Ed25519', 'RS256', 'PS256', 'HS256'];

async function keysFor(alg) {
    if (alg === 'HS256') {
        const secret = crypto.createSecretKey(crypto.randomBytes(32));
        const other = crypto.createSecretKey(crypto.randomBytes(32));
        return { signKey: secret, verifyKey: secret, wrongKey: other };
    }
    const pair = await generateKeyPair(alg, { extractable: true });
    const other = await generateKeyPair(alg, { extractable: true });
    return { signKey: pair.privateKey, verifyKey: pair.publicKey, wrongKey: other.publicKey };
}

async function challenge(file) {
    const now = Math.floor(Date.now() / 1000);
    const verify = [];
    for (const alg of ALGORITHMS) {
        const keys = await keysFor(alg);
        const jwk = JSON.stringify(await exportJWK(keys.verifyKey));
        const wrongJwk = JSON.stringify(await exportJWK(keys.wrongKey));
        const make = (adjust = (jwt) => jwt, header = { alg, typ: 'at+jwt' }) =>
            adjust(
                new SignJWT({ scope: 'read' })
                    .setProtectedHeader(header)
                    .setIssuer('https://issuer.example')
                    .setAudience(['https://api.example', 'https://other.example'])
                    .setExpirationTime(now + 60)
                    .setNotBefore(now - 60),
            ).sign(keys.signKey);
        const good = await make();
        const [header, , signature] = good.split('.');
        const all = { issuer: 'https://issuer.example', audience: 'https://api.example', typ: 'at+jwt' };
        const variants = [
            { token: good, options: all },
            { token: good, options: {} },
            { token: good, options: { ...all, audience: 'https://other.example' } },
            { token: good, options: { ...all, issuer: 'https://evil.example' } },
            { token: good, options: { ...all, audience: 'https://evil.example' } },
            { token: good, options: { ...all, typ: 'JWT' } },
            { token: good, options: all, wrongKey: true },
            { token: `${header}.${base64url.encode('{"iss":"https://issuer.example"}')}.${signature}`, options: {} },
            { token: await make((jwt) => jwt.setExpirationTime(now)), options: all },
            { token: await make((jwt) => jwt.setExpirationTime(now - 30)), options: { ...all, clockTolerance: 31 } },
            { token: await make((jwt) => jwt.setExpirationTime(now - 30)), options: { ...all, clockTolerance: 30 } },
            { token: await make((jwt) => jwt.setNotBefore(now + 10)), options: all },
            { token: await make((jwt) => jwt.setNotBefore(now + 10)), options: { ...all, clockTolerance: 10 } },
            { token: await make((jwt) => jwt, { alg }), options: all },
        ];
        for (const variant of variants) {
            let expected;
            try {
                await jwtVerify(variant.token, variant.wrongKey ? keys.wrongKey : keys.verifyKey, {
                    ...variant.options,
                    currentDate: new Date(now * 1000),
                });
                expected = true;
            } catch {
                expected = false;
            }
            verify.push({
                algorithm: alg,
                jwk: variant.wrongKey ? wrongJwk : jwk,
                token: variant.token,
                issuer: variant.options.issuer,
                audience: variant.options.audience,
                typ: variant.options.typ,
                clockTolerance: variant.options.clockTolerance,
                expected,
            });
        }
    }

    const hmacJwk = JSON.stringify(await exportJWK(crypto.createSecretKey(crypto.randomBytes(32))));
    fs.writeFileSync(file, JSON.stringify({ now, hmacJwk, verify }));
}

async function verify(challengeFile, responseFile) {
    const challenge = JSON.parse(fs.readFileSync(challengeFile, 'utf8'));
    const response = JSON.parse(fs.readFileSync(responseFile, 'utf8'));
    const now = challenge.now;
    const failures = [];
    const counts = {};

    function check(section, label, condition, detail) {
        counts[section] = (counts[section] ?? 0) + 1;
        if (!condition) {
            failures.push(`${section} ${label}: ${detail}`);
        }
    }

    function sameJSON(actual, expected) {
        try {
            assert.deepEqual(actual, expected);
            return true;
        } catch {
            return false;
        }
    }

    async function refuses(section, label, run) {
        try {
            await run();
            check(section, label, false, 'jose accepted it');
        } catch {
            check(section, label, true, '');
        }
    }

    check('algorithms covered', '', sameJSON(response.produced.map((p) => p.algorithm), ALGORITHMS), response.produced.map((p) => p.algorithm).join(','));

    const options = { issuer: 'https://issuer.example', audience: 'https://api.example', currentDate: new Date(now * 1000) };
    for (const item of response.produced) {
        const label = item.algorithm;
        const key = await importJWK(JSON.parse(item.jwk), item.algorithm);

        try {
            const { payload, protectedHeader } = await jwtVerify(item.built, key, { ...options, typ: 'at+jwt' });
            check('builder token accepted', label, true, '');
            check('builder token claims', label, sameJSON(payload, {
                iss: 'https://issuer.example',
                sub: 'user-123',
                aud: 'https://api.example',
                exp: now + 300,
                nbf: now,
                iat: now,
                jti: 'built-1',
                scope: 'read write',
                nested: { flag: true, list: [1, 'two'] },
            }), JSON.stringify(payload));
            check('builder token header', label, protectedHeader.alg === item.algorithm && protectedHeader.typ === 'at+jwt', JSON.stringify(protectedHeader));
        } catch (error) {
            check('builder token accepted', label, false, `jose rejected it: ${error.code}: ${error.message}`);
        }

        // Acceptance above only means something if jose's checks bite on the same token.
        await refuses('refused for another issuer', label, () => jwtVerify(item.built, key, { ...options, issuer: 'https://evil.example' }));
        await refuses('refused for another audience', label, () => jwtVerify(item.built, key, { ...options, audience: 'https://evil.example' }));
        await refuses('refused for another typ', label, () => jwtVerify(item.built, key, { ...options, typ: 'JWT' }));
        await refuses('refused once expired', label, () => jwtVerify(item.built, key, { ...options, currentDate: new Date((now + 300) * 1000) }));
        await refuses('refused before nbf', label, () => jwtVerify(item.built, key, { ...options, currentDate: new Date((now - 1) * 1000) }));
        const [header, , signature] = item.built.split('.');
        await refuses('refused with altered claims', label, () => jwtVerify(`${header}.${base64url.encode('{"iss":"https://issuer.example","aud":"https://api.example"}')}.${signature}`, key, options));

        try {
            const { payload, protectedHeader } = await jwtVerify(item.typed, key, { ...options, audience: 'https://other.example', typ: 'JWT' });
            check('typed token accepted', label, true, '');
            check('typed token claims', label, sameJSON(payload, {
                iss: 'https://issuer.example',
                sub: 'user-456',
                aud: ['https://api.example', 'https://other.example'],
                exp: now + 60,
                scope: 'admin',
                tenant: 7,
                roles: ['a', 'b'],
                'https://example.com/claim': 'namespaced',
            }), JSON.stringify(payload));
            check('typed token header', label, protectedHeader.nonce === 'n-1', JSON.stringify(protectedHeader));
        } catch (error) {
            check('typed token accepted', label, false, `jose rejected it: ${error.code}: ${error.message}`);
        }
    }

    check('verdict count', '', response.verdicts.length === challenge.verify.length, `${response.verdicts.length}`);
    for (const [index, item] of challenge.verify.entries()) {
        check(
            item.expected ? 'Swift accepts JWT jose accepts' : 'Swift rejects JWT jose rejects',
            `[${index}] ${item.algorithm}`,
            response.verdicts[index] === item.expected,
            `Swift said ${response.verdicts[index]}`,
        );
    }
    check('challenge has both verdicts', '', (counts['Swift accepts JWT jose accepts'] ?? 0) > 0 && (counts['Swift rejects JWT jose rejects'] ?? 0) > 0, '');

    for (const [section, count] of Object.entries(counts)) {
        console.log(`${section}: ${count} checked`);
    }
    if (failures.length > 0) {
        console.error(`\n${failures.length} FAILURES`);
        for (const failure of failures.slice(0, 20)) {
            console.error(`  ${failure}`);
        }
        process.exit(1);
    }
    console.log('closed loop: all checks passed');
}

const [command, ...files] = process.argv.slice(2);
if (command === 'challenge' && files.length === 1) {
    await challenge(files[0]);
} else if (command === 'verify' && files.length === 2) {
    await verify(files[0], files[1]);
} else {
    console.error('usage: closed-loop.mjs challenge <challenge.json> | verify <challenge.json> <response.json>');
    process.exit(2);
}
