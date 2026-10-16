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
import { ENCRYPTIONS, decryptOptions, flipLastBit, keyManagementSetups } from './common.mjs';

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

    fs.writeFileSync(file, JSON.stringify({ plaintext: plaintext.toString('hex'), additionalData: additionalData.toString('hex'), encrypt, multiple, decrypt }));
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

    async function refuses(section, label, run) {
        try {
            await run();
            check(section, label, false, 'jose decrypted it');
        } catch {
            check(section, label, true, '');
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
    check('challenge has both outcomes', '', (counts['Swift decrypts what jose decrypts'] ?? 0) > 0 && (counts['Swift refuses what jose refuses'] ?? 0) > 0, '');

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
