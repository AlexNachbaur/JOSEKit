// Closed-loop interoperability check. The counterpart sets a challenge, the Swift package
// answers it, and the counterpart judges the answers.
//
//     node closed-loop.mjs challenge <challenge.json>
//     swift run jose-jwe-interop < challenge.json > response.json
//     node closed-loop.mjs verify <challenge.json> <response.json>
//
// `scripts/interop.sh` runs all three. `verify` exits non-zero on any disagreement.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { CompactEncrypt, FlattenedEncrypt, GeneralEncrypt, base64url, compactDecrypt, flattenedDecrypt, generalDecrypt, importJWK } from 'jose';
import { runClosedLoop } from '../shared/closed-loop.mjs';
import { flipLastBit } from '../shared/fixtures.mjs';
import { ENCRYPTIONS, decryptOptions, keyManagementSetups } from './common.mjs';

async function challenge(file) {
    const plaintext = crypto.randomBytes(200);
    const additionalData = crypto.randomBytes(24);
    const encrypt = [];
    const decrypt = [];

    for (const setup of keyManagementSetups()) {
        for (const encryption of ENCRYPTIONS) {
            // Keys this package will encrypt to. The private half stays here, in `decryptJwk`,
            // which the Swift program does not read.
            const keys = await setup.keys(encryption);
            encrypt.push({
                label: `${setup.label} / ${encryption.enc}`,
                algorithm: setup.alg,
                encryption: encryption.enc,
                jwk: JSON.stringify(keys.encryptJwk),
                decryptJwk: JSON.stringify(keys.decryptJwk),
            });

            // JWEs for this package to open: intact, altered, and for someone else's key.
            const mine = await setup.keys(encryption);
            const other = await setup.keys(encryption);
            const message = crypto.randomBytes(1 + crypto.randomInt(0, 100));
            const compact = await new CompactEncrypt(message).setProtectedHeader({ alg: setup.alg, enc: encryption.enc }).encrypt(mine.encryptKey);
            const parts = compact.split('.');
            const flip = (segment) => base64url.encode(flipLastBit(Buffer.from(base64url.decode(segment))));
            const flattened = await new FlattenedEncrypt(message)
                .setProtectedHeader({ alg: setup.alg, enc: encryption.enc })
                .setAdditionalAuthenticatedData(additionalData)
                .encrypt(mine.encryptKey);
            const variants = [
                { serialization: 'compact', token: compact, key: mine },
                { serialization: 'compact', token: compact, key: other },
                { serialization: 'compact', token: [parts[0], parts[1], parts[2], flip(parts[3]), parts[4]].join('.'), key: mine },
                { serialization: 'compact', token: [parts[0], parts[1], parts[2], parts[3], flip(parts[4])].join('.'), key: mine },
                { serialization: 'json', token: JSON.stringify(flattened), key: mine },
                { serialization: 'json', token: JSON.stringify({ ...flattened, aad: base64url.encode('other') }), key: mine },
            ];
            for (const variant of variants) {
                let expected;
                try {
                    const result = variant.serialization === 'compact'
                        ? await compactDecrypt(variant.token, variant.key.decryptKey, decryptOptions(setup.alg))
                        : await flattenedDecrypt(JSON.parse(variant.token), variant.key.decryptKey, decryptOptions(setup.alg));
                    expected = { accepted: true, plaintext: Buffer.from(result.plaintext).toString('hex') };
                } catch {
                    expected = { accepted: false };
                }
                decrypt.push({
                    algorithm: setup.alg,
                    jwk: JSON.stringify(variant.key.decryptJwk),
                    serialization: variant.serialization,
                    token: variant.token,
                    expected,
                });
            }
        }
    }

    // One JWE for three recipients with different algorithms.
    const setups = keyManagementSetups();
    const multiple = [];
    for (const label of ['RSA-OAEP-256', 'ECDH-ES+A256KW X25519', 'A192GCMKW']) {
        const setup = setups.find((candidate) => candidate.label === label);
        const keys = await setup.keys(ENCRYPTIONS[5]);
        multiple.push({ algorithm: setup.alg, encryption: 'A256CBC-HS512', jwk: JSON.stringify(keys.encryptJwk), decryptJwk: JSON.stringify(keys.decryptJwk) });
    }

    // Compression (zip: DEF): one key both sides use, a plaintext that compresses well, and JWEs
    // jose compressed for this package to open. The second expands past the default limit both
    // implementations share (250 000 bytes), so both should refuse it.
    const zipKey = crypto.randomBytes(32);
    const zipPlaintext = Buffer.from('the quick brown fox jumps over the lazy dog. '.repeat(100));
    const zipTokens = [];
    for (const content of [zipPlaintext, Buffer.alloc(300_000)]) {
        const token = await new CompactEncrypt(content)
            .setProtectedHeader({ alg: 'A256KW', enc: 'A256GCM', zip: 'DEF' })
            .encrypt(zipKey);
        let expected;
        try {
            const result = await compactDecrypt(token, zipKey);
            expected = { accepted: true, plaintext: Buffer.from(result.plaintext).toString('hex') };
        } catch {
            expected = { accepted: false };
        }
        zipTokens.push({ token, expected });
    }
    const compression = {
        jwk: JSON.stringify({ kty: 'oct', k: base64url.encode(zipKey) }),
        plaintext: zipPlaintext.toString('hex'),
        tokens: zipTokens,
    };

    fs.writeFileSync(file, JSON.stringify({ plaintext: plaintext.toString('hex'), additionalData: additionalData.toString('hex'), encrypt, multiple, decrypt, compression }));
}

async function verify(challenge, response, checks) {
    const { check, count } = checks;
    const refuses = (section, label, run) => checks.refuses(section, label, run, 'jose decrypted it');

    async function opens(section, label, run, expectedAad) {
        try {
            const result = await run();
            check(section, label, Buffer.from(result.plaintext).toString('hex') === challenge.plaintext, 'plaintext differs');
            if (expectedAad !== undefined) {
                check(`${section}: additional data`, label, Buffer.from(result.additionalAuthenticatedData ?? []).toString('hex') === expectedAad, 'aad differs');
            }
            return result;
        } catch (error) {
            check(section, label, false, `jose could not decrypt it: ${error.code ?? error.name}: ${error.message}`);
            return undefined;
        }
    }

    check('produced count', '', response.produced.length === challenge.encrypt.length, `${response.produced.length}`);
    for (const [index, item] of challenge.encrypt.entries()) {
        const produced = response.produced[index];
        if (!produced) continue;
        const key = await importJWK(JSON.parse(item.decryptJwk), item.algorithm);
        const options = decryptOptions(item.algorithm);

        const result = await opens('compact decrypted by jose', item.label, () => compactDecrypt(produced.compact, key, options));
        if (result) {
            const header = result.protectedHeader;
            check('compact header', item.label, header.alg === item.algorithm && header.enc === item.encryption && header.typ === 'example+jwe', JSON.stringify(header));
        }
        // Decryption above only means something if jose refuses the same JWE once altered.
        const parts = produced.compact.split('.');
        const flip = (segment) => base64url.encode(flipLastBit(Buffer.from(base64url.decode(segment))));
        await refuses('compact with altered ciphertext refused', item.label, () => compactDecrypt([parts[0], parts[1], parts[2], flip(parts[3]), parts[4]].join('.'), key, options));
        await refuses('compact with altered tag refused', item.label, () => compactDecrypt([parts[0], parts[1], parts[2], parts[3], flip(parts[4])].join('.'), key, options));

        const flattened = JSON.parse(produced.flattened);
        await opens('flattened with additional data decrypted by jose', item.label, () => flattenedDecrypt(flattened, key, options), challenge.additionalData);
        await refuses('flattened with altered additional data refused', item.label, () => flattenedDecrypt({ ...flattened, aad: base64url.encode('other') }, key, options));
    }

    const general = JSON.parse(response.multiple);
    check('general has three recipients', '', general.recipients?.length === 3, JSON.stringify(general.recipients?.length));
    for (const [index, item] of challenge.multiple.entries()) {
        const key = await importJWK(JSON.parse(item.decryptJwk), item.algorithm);
        const result = await opens('general decrypted by each recipient', item.algorithm, () => generalDecrypt(general, key), challenge.additionalData);
        if (result) {
            check('general recipient header', item.algorithm, result.unprotectedHeader?.alg === item.algorithm && result.unprotectedHeader?.kid === `recipient-${index}`, JSON.stringify(result.unprotectedHeader));
        }
    }

    check('outcome count', '', response.outcomes.length === challenge.decrypt.length, `${response.outcomes.length}`);
    for (const [index, item] of challenge.decrypt.entries()) {
        const outcome = response.outcomes[index] ?? {};
        const label = `[${index}] ${item.algorithm} ${item.serialization}`;
        if (item.expected.accepted) {
            check('Swift decrypts what jose decrypts', label, outcome.accepted === true && outcome.plaintext === item.expected.plaintext, JSON.stringify(outcome));
        } else {
            check('Swift refuses what jose refuses', label, outcome.accepted === false, JSON.stringify(outcome));
        }
    }
    check('challenge has both outcomes', '', count('Swift decrypts what jose decrypts') > 0 && count('Swift refuses what jose refuses') > 0, '');

    // Compression, both ways.
    const zipKey = base64url.decode(JSON.parse(challenge.compression.jwk).k);
    try {
        const result = await compactDecrypt(response.compressed, zipKey);
        check('compressed JWE decrypted by jose', '', Buffer.from(result.plaintext).toString('hex') === challenge.compression.plaintext, 'plaintext differs');
        check('compressed JWE header', '', result.protectedHeader.zip === 'DEF', JSON.stringify(result.protectedHeader));
        const ciphertextLength = base64url.decode(response.compressed.split('.')[3]).length;
        check('compressed JWE is smaller', '', ciphertextLength < challenge.compression.plaintext.length / 2 / 4, `${ciphertextLength}`);
    } catch (error) {
        check('compressed JWE decrypted by jose', '', false, `jose could not decrypt it: ${error.code ?? error.name}: ${error.message}`);
    }
    check('compressed outcome count', '', response.compressedOutcomes.length === challenge.compression.tokens.length, `${response.compressedOutcomes.length}`);
    for (const [index, item] of challenge.compression.tokens.entries()) {
        const outcome = response.compressedOutcomes[index] ?? {};
        check('Swift agrees with jose on compressed JWEs', `[${index}]`, outcome.accepted === item.expected.accepted && (outcome.plaintext ?? null) === (item.expected.plaintext ?? null), JSON.stringify(outcome));
    }
    check('compressed challenge has both outcomes', '', challenge.compression.tokens.some((item) => item.expected.accepted) && challenge.compression.tokens.some((item) => !item.expected.accepted), '');
}

await runClosedLoop({ challenge, verify });
