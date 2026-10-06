// Closed-loop interoperability check for encrypted and nested JWTs. The counterpart sets a
// challenge, the Swift package answers it, and the counterpart judges the answers.
//
//     node closed-loop-encrypted.mjs challenge <challenge.json>
//     swift run jose-jwt-encrypted-interop < challenge.json > response.json
//     node closed-loop-encrypted.mjs verify <challenge.json> <response.json>
//
// `scripts/interop.sh` runs all three. `verify` exits non-zero on any disagreement.

import assert from 'node:assert/strict';
import crypto from 'node:crypto';
import fs from 'node:fs';
import { CompactEncrypt, EncryptJWT, SignJWT, base64url, compactDecrypt, exportJWK, generateKeyPair, importJWK, jwtDecrypt, jwtVerify } from 'jose';
import { recipients } from './generate-encrypted-fixtures.mjs';

const ISSUER = 'https://issuer.example';
const AUDIENCE = 'https://api.example';

async function challenge(file) {
    const now = Math.floor(Date.now() / 1000);
    const currentDate = new Date(now * 1000);
    const all = await recipients();

    // Keys for the Swift side to encrypt to. The private half stays here, in `decryptJwk`,
    // which the Swift program does not read.
    const recipientEntries = [];
    for (const recipient of all) {
        recipientEntries.push({
            algorithm: recipient.alg,
            encryption: recipient.enc,
            jwk: JSON.stringify(await exportJWK(recipient.encryptKey)),
            decryptJwk: JSON.stringify(await exportJWK(recipient.decryptKey)),
        });
    }

    // Tokens for the Swift side to judge.
    const signer = await generateKeyPair('ES256', { extractable: true });
    const stranger = await generateKeyPair('ES256', { extractable: true });
    const signerJwk = JSON.stringify(await exportJWK(signer.publicKey));
    const verify = [];
    for (const recipient of all) {
        const other = (await recipients()).find((candidate) => candidate.alg === recipient.alg);
        const jwk = JSON.stringify(await exportJWK(recipient.decryptKey));
        const otherJwk = JSON.stringify(await exportJWK(other.decryptKey));
        const encrypt = (adjust = (jwt) => jwt) =>
            adjust(new EncryptJWT({ scope: 'read' }).setProtectedHeader({ alg: recipient.alg, enc: recipient.enc }).setIssuer(ISSUER).setAudience(AUDIENCE).setExpirationTime(now + 60)).encrypt(recipient.encryptKey);
        const sign = (key, adjust = (jwt) => jwt) =>
            adjust(new SignJWT({ scope: 'read' }).setProtectedHeader({ alg: 'ES256' }).setIssuer(ISSUER).setAudience(AUDIENCE).setExpirationTime(now + 60)).sign(key);
        const nest = async (inner, header = { cty: 'JWT' }) =>
            new CompactEncrypt(Buffer.from(inner, 'utf8')).setProtectedHeader({ alg: recipient.alg, enc: recipient.enc, ...header }).encrypt(recipient.encryptKey);
        const good = await encrypt();
        const options = { issuer: ISSUER, audience: AUDIENCE };
        const variants = [
            { token: good, options, jwk },
            { token: good, options, jwk: otherJwk },
            { token: good, options: { ...options, audience: 'https://evil.example' }, jwk },
            { token: await encrypt((jwt) => jwt.setExpirationTime(now - 1)), options, jwk },
            { token: await encrypt((jwt) => jwt.replicateIssuerAsHeader()), options, jwk },
            { token: await nest(await sign(signer.privateKey)), options, jwk, signerJwk },
            { token: await nest(await sign(stranger.privateKey)), options, jwk, signerJwk },
            { token: await nest(await sign(signer.privateKey, (jwt) => jwt.setExpirationTime(now - 1))), options, jwk, signerJwk },
            { token: await nest(await sign(signer.privateKey)), options, jwk: otherJwk, signerJwk },
            { token: await nest(await sign(signer.privateKey), {}), options, jwk, signerJwk },
        ];
        for (const variant of variants) {
            let expected;
            try {
                const key = await importJWK(JSON.parse(variant.jwk), recipient.alg);
                if (variant.signerJwk) {
                    const { plaintext, protectedHeader } = await compactDecrypt(variant.token, key);
                    if (protectedHeader.cty !== 'JWT') throw new Error('not nested');
                    await jwtVerify(Buffer.from(plaintext).toString('utf8'), signer.publicKey, { ...variant.options, currentDate });
                } else {
                    await jwtDecrypt(variant.token, key, { ...variant.options, currentDate });
                }
                expected = true;
            } catch {
                expected = false;
            }
            verify.push({
                algorithm: recipient.alg,
                jwk: variant.jwk,
                token: variant.token,
                signerJwk: variant.signerJwk,
                issuer: variant.options.issuer,
                audience: variant.options.audience,
                expected,
            });
        }
    }

    fs.writeFileSync(file, JSON.stringify({ now, recipients: recipientEntries, verify }));
}

async function verify(challengeFile, responseFile) {
    const challenge = JSON.parse(fs.readFileSync(challengeFile, 'utf8'));
    const response = JSON.parse(fs.readFileSync(responseFile, 'utf8'));
    const now = challenge.now;
    const currentDate = new Date(now * 1000);
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

    const expectedClaims = {
        iss: ISSUER,
        sub: 'user-123',
        aud: AUDIENCE,
        exp: now + 300,
        iat: now,
        scope: 'read write',
    };
    const options = { issuer: ISSUER, audience: AUDIENCE, currentDate };

    check('produced count', '', response.produced.length === challenge.recipients.length, `${response.produced.length}`);
    for (const [index, recipient] of challenge.recipients.entries()) {
        const produced = response.produced[index];
        if (!produced) continue;
        const label = recipient.algorithm;
        const key = await importJWK(JSON.parse(recipient.decryptJwk), recipient.algorithm);

        try {
            const { payload, protectedHeader } = await jwtDecrypt(produced.encrypted, key, { ...options, typ: 'JWT' });
            check('encrypted JWT accepted by jose', label, true, '');
            check('encrypted JWT claims', label, sameJSON(payload, expectedClaims), JSON.stringify(payload));
            check('encrypted JWT header', label, protectedHeader.alg === recipient.algorithm && protectedHeader.enc === recipient.encryption && protectedHeader.cty === undefined, JSON.stringify(protectedHeader));
        } catch (error) {
            check('encrypted JWT accepted by jose', label, false, `jose rejected it: ${error.code}: ${error.message}`);
        }
        await refuses('encrypted JWT refused for another audience', label, () => jwtDecrypt(produced.encrypted, key, { ...options, audience: 'https://evil.example' }));
        await refuses('encrypted JWT refused once expired', label, () => jwtDecrypt(produced.encrypted, key, { ...options, currentDate: new Date((now + 300) * 1000) }));
        const parts = produced.encrypted.split('.');
        const tag = Buffer.from(base64url.decode(parts[4]));
        tag[0] ^= 1;
        await refuses('encrypted JWT refused when altered', label, () => jwtDecrypt([parts[0], parts[1], parts[2], parts[3], base64url.encode(tag)].join('.'), key, options));

        try {
            const { plaintext, protectedHeader } = await compactDecrypt(produced.nested, key);
            check('nested JWT outer header', label, protectedHeader.cty === 'JWT' && protectedHeader.alg === recipient.algorithm, JSON.stringify(protectedHeader));
            const inner = Buffer.from(plaintext).toString('utf8');
            const signerKey = await importJWK(JSON.parse(produced.signerJwk), 'ES256');
            const { payload, protectedHeader: innerHeader } = await jwtVerify(inner, signerKey, options);
            check('nested JWT inner verified by jose', label, true, '');
            check('nested JWT inner claims', label, sameJSON(payload, expectedClaims), JSON.stringify(payload));
            check('nested JWT inner header', label, innerHeader.alg === 'ES256' && innerHeader.typ === 'JWT' && innerHeader.kid === 'sig', JSON.stringify(innerHeader));
            const otherSigner = await generateKeyPair('ES256');
            await refuses('nested JWT inner refused under another key', label, () => jwtVerify(inner, otherSigner.publicKey, options));
        } catch (error) {
            check('nested JWT inner verified by jose', label, false, `jose rejected it: ${error.code}: ${error.message}`);
        }
    }

    check('verdict count', '', response.verdicts.length === challenge.verify.length, `${response.verdicts.length}`);
    for (const [index, item] of challenge.verify.entries()) {
        const kind = item.signerJwk ? 'nested' : 'encrypted';
        check(
            item.expected ? `Swift accepts ${kind} JWT jose accepts` : `Swift rejects ${kind} JWT jose rejects`,
            `[${index}] ${item.algorithm}`,
            response.verdicts[index] === item.expected,
            `Swift said ${response.verdicts[index]}`,
        );
    }

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
    console.log('closed loop (encrypted): all checks passed');
}

const [command, ...files] = process.argv.slice(2);
if (command === 'challenge' && files.length === 1) {
    await challenge(files[0]);
} else if (command === 'verify' && files.length === 2) {
    await verify(files[0], files[1]);
} else {
    console.error('usage: closed-loop-encrypted.mjs challenge <challenge.json> | verify <challenge.json> <response.json>');
    process.exit(2);
}
