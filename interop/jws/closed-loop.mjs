// Closed-loop interoperability check. The counterpart sets a challenge, the Swift package
// answers it, and the counterpart judges the answers.
//
//     node closed-loop.mjs challenge <challenge.json>
//     swift run jose-jws-interop < challenge.json > response.json
//     node closed-loop.mjs verify <challenge.json> <response.json>
//
// `scripts/interop.sh` runs all three. `verify` exits non-zero on any disagreement.

import crypto from 'node:crypto';
import fs from 'node:fs';
import {
    CompactSign, FlattenedSign, GeneralSign, base64url, compactVerify, exportJWK, flattenedVerify, generalVerify,
    generateKeyPair, importJWK,
} from 'jose';
import { ASYMMETRIC, HMAC, RSA_ALGORITHMS } from './common.mjs';

async function challenge(file) {
    const hmacKeys = [];
    for (const spec of HMAC) {
        const secret = crypto.createSecretKey(crypto.randomBytes(spec.byteCount));
        hmacKeys.push({ algorithm: spec.alg, jwk: JSON.stringify(await exportJWK(secret)) });
    }

    // JWSs for the Swift side to judge. `expected` is jose's own verdict; the Swift program does
    // not read it.
    const verify = [];
    const setups = [];
    for (const kind of ASYMMETRIC) {
        for (const alg of kind.algs) {
            const pair = await generateKeyPair(kind.joseAlg, { extractable: true });
            const other = await generateKeyPair(kind.joseAlg, { extractable: true });
            setups.push({ alg, signKey: pair.privateKey, verifyKey: pair.publicKey, wrongKey: other.publicKey });
        }
    }
    for (const alg of RSA_ALGORITHMS) {
        const pair = await generateKeyPair(alg, { extractable: true });
        const other = await generateKeyPair(alg, { extractable: true });
        setups.push({ alg, signKey: pair.privateKey, verifyKey: pair.publicKey, wrongKey: other.publicKey });
    }
    for (const spec of HMAC) {
        setups.push({
            alg: spec.alg,
            signKey: crypto.createSecretKey(crypto.randomBytes(spec.byteCount)),
            wrongKey: crypto.createSecretKey(crypto.randomBytes(spec.byteCount)),
        });
    }
    for (const setup of setups) {
        setup.verifyKey ??= setup.signKey;
        const jwk = JSON.stringify(await exportJWK(setup.verifyKey));
        const wrongJwk = JSON.stringify(await exportJWK(setup.wrongKey));
        for (let i = 0; i < 5; i++) {
            const payload = crypto.randomBytes(1 + i * 30);
            const compact = await new CompactSign(payload).setProtectedHeader({ alg: setup.alg }).sign(setup.signKey);
            const [header, body, signature] = compact.split('.');
            const flattened = await new FlattenedSign(payload)
                .setProtectedHeader({ alg: setup.alg })
                .setUnprotectedHeader({ 'urn:example:note': 'x' })
                .sign(setup.signKey);
            const general = await new GeneralSign(payload)
                .addSignature(setup.signKey)
                .setProtectedHeader({ alg: setup.alg })
                .sign();
            const variants = [
                { serialization: 'compact', token: compact, key: 'right' },
                { serialization: 'compact', token: compact, key: 'wrong' },
                { serialization: 'compact', token: `${header}.${base64url.encode(crypto.randomBytes(8))}.${signature}`, key: 'right' },
                { serialization: 'compact', token: `${base64url.encode(JSON.stringify({ alg: 'none' }))}.${body}.`, key: 'right' },
                { serialization: 'json', token: JSON.stringify(flattened), key: 'right' },
                { serialization: 'json', token: JSON.stringify({ ...flattened, payload: base64url.encode('other') }), key: 'right' },
                { serialization: 'json', token: JSON.stringify(general), key: 'right' },
                { serialization: 'json', token: JSON.stringify(general), key: 'wrong' },
            ];
            for (const variant of variants) {
                const key = variant.key === 'right' ? setup.verifyKey : setup.wrongKey;
                let expected;
                try {
                    const result =
                        variant.serialization === 'compact'
                            ? await compactVerify(variant.token, key)
                            : await (JSON.parse(variant.token).signatures ? generalVerify : flattenedVerify)(JSON.parse(variant.token), key);
                    expected = { accepted: true, payload: Buffer.from(result.payload).toString('hex') };
                } catch {
                    expected = { accepted: false };
                }
                verify.push({
                    algorithm: setup.alg,
                    jwk: variant.key === 'right' ? jwk : wrongJwk,
                    serialization: variant.serialization,
                    token: variant.token,
                    expected,
                });
            }
        }
    }

    fs.writeFileSync(
        file,
        JSON.stringify({
            payload: crypto.randomBytes(120).toString('hex'),
            unencodedPayload: '{"amount":"12.50","note":"a.b.c é \\"quoted\\""}',
            hmacKeys,
            verify,
        }),
    );
}

async function verify(challengeFile, responseFile) {
    const challenge = JSON.parse(fs.readFileSync(challengeFile, 'utf8'));
    const response = JSON.parse(fs.readFileSync(responseFile, 'utf8'));
    const failures = [];
    const counts = {};

    function check(section, label, condition, detail) {
        counts[section] = (counts[section] ?? 0) + 1;
        if (!condition) {
            failures.push(`${section} ${label}: ${detail}`);
        }
    }

    // Runs a jose verification and reports whether it accepted and returned the expected payload.
    async function accepts(section, label, run, expectedPayloadHex) {
        try {
            const result = await run();
            const payload = Buffer.from(result.payload).toString('hex');
            check(section, label, payload === expectedPayloadHex, `payload ${payload}`);
            return result;
        } catch (error) {
            check(section, label, false, `jose rejected it: ${error.code ?? error.name}: ${error.message}`);
            return undefined;
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

    const unencodedHex = Buffer.from(challenge.unencodedPayload, 'utf8').toString('hex');
    const expectedAlgorithms = ['ES256', 'ES384', 'ES512', 'Ed25519', 'EdDSA', ...RSA_ALGORITHMS, 'HS256', 'HS384', 'HS512'];
    check('algorithms covered', '', JSON.stringify(response.produced.map((p) => p.algorithm)) === JSON.stringify(expectedAlgorithms), response.produced.map((p) => p.algorithm).join(','));

    for (const item of response.produced) {
        const label = item.algorithm;
        const key = await importJWK(JSON.parse(item.jwk), item.algorithm);
        const second = await importJWK(JSON.parse(item.generalSecondJwk), 'ES256');

        const compact = await accepts('compact accepted', label, () => compactVerify(item.compact, key), challenge.payload);
        if (compact) {
            check('compact header alg', label, compact.protectedHeader.alg === item.algorithm, compact.protectedHeader.alg);
            check('compact header typ', label, compact.protectedHeader.typ === 'example+jws', compact.protectedHeader.typ);
        }

        // Acceptance above is only meaningful if the same token fails once altered.
        const [header, body, signature] = item.compact.split('.');
        await refuses('compact with altered payload refused', label, () => compactVerify(`${header}.${base64url.encode('x')}.${signature}`, key));
        const sig = Buffer.from(base64url.decode(signature));
        sig[sig.length - 1] ^= 0x01;
        await refuses('compact with altered signature refused', label, () => compactVerify(`${header}.${body}.${base64url.encode(sig)}`, key));

        const [dHeader, dBody, dSignature] = item.compactDetached.split('.');
        check('detached compact has no payload', label, dBody === '', dBody);
        await accepts('detached compact accepted with payload restored', label, () => compactVerify(`${dHeader}.${base64url.encode(Buffer.from(challenge.payload, 'hex'))}.${dSignature}`, key), challenge.payload);

        await accepts('flattened accepted', label, () => flattenedVerify(JSON.parse(item.flattened), key), challenge.payload);
        await accepts('general accepted with first key', label, () => generalVerify(JSON.parse(item.general), key), challenge.payload);
        await accepts('general accepted with second key', label, () => generalVerify(JSON.parse(item.general), second), challenge.payload);
        check('general has two signatures', label, JSON.parse(item.general).signatures.length === 2, '');

        const unencoded = JSON.parse(item.unencodedDetached);
        check('unencoded token is detached', label, !('payload' in unencoded), 'payload present');
        const unencodedResult = await accepts('unencoded (RFC 7797) accepted', label, () => flattenedVerify({ ...unencoded, payload: challenge.unencodedPayload }, key), unencodedHex);
        if (unencodedResult) {
            check('unencoded header', label, unencodedResult.protectedHeader.b64 === false && unencodedResult.protectedHeader.crit.includes('b64'), JSON.stringify(unencodedResult.protectedHeader));
        }
        await refuses('unencoded with other payload refused', label, () => flattenedVerify({ ...unencoded, payload: challenge.unencodedPayload + '!' }, key));

        // A critical extension: jose must refuse it unless told the extension is understood.
        await refuses('critical extension refused when not understood', label, () => compactVerify(item.customHeader, key));
        const custom = await accepts('critical extension accepted when understood', label, () => compactVerify(item.customHeader, key, { crit: { 'urn:example:must': true } }), challenge.payload);
        if (custom) {
            check('custom header values', label, custom.protectedHeader['urn:example:level'] === 7 && custom.protectedHeader['urn:example:must'] === 'understood', JSON.stringify(custom.protectedHeader));
        }
    }

    check('verdict count', '', response.verdicts.length === challenge.verify.length, `${response.verdicts.length}`);
    for (const [index, item] of challenge.verify.entries()) {
        const verdict = response.verdicts[index] ?? {};
        const label = `[${index}] ${item.algorithm} ${item.serialization}`;
        if (item.expected.accepted) {
            check('Swift accepts valid jose JWS', label, verdict.accepted === true && verdict.payload === item.expected.payload, JSON.stringify(verdict));
        } else {
            check('Swift rejects invalid jose JWS', label, verdict.accepted === false, JSON.stringify(verdict));
        }
    }
    check('challenge has both verdicts', '', (counts['Swift accepts valid jose JWS'] ?? 0) > 0 && (counts['Swift rejects invalid jose JWS'] ?? 0) > 0, '');

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
