// Generates the fixtures in Tests/JOSEJWETests/Fixtures by running the counterpart
// implementation, panva/jose.
//
//     cd interop && npm ci && node generate-fixtures.mjs
//
// Every JWE is produced by jose, and every verdict on a malformed one is jose's own. Nothing is
// transcribed from a specification. The fixtures change on every run because keys, IVs and
// ephemeral keys are random.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { CompactEncrypt, FlattenedEncrypt, GeneralEncrypt, base64url, compactDecrypt, exportJWK, flattenedDecrypt, generalDecrypt, generateKeyPair } from 'jose';
import { ENCRYPTIONS, flipLastBit, joseVersion, keyManagementSetups } from './common.mjs';

const fixturesDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../Tests/JOSEJWETests/Fixtures');

function write(name, description, body) {
    const fixture = {
        _generated: {
            notice: 'GENERATED FILE. Do not edit by hand; rerun interop/generate-fixtures.mjs.',
            generator: 'interop/generate-fixtures.mjs',
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

async function validFixture() {
    const compact = [];
    for (const setup of keyManagementSetups()) {
        for (const encryption of ENCRYPTIONS) {
            const keys = await setup.keys(encryption);
            const plaintext = crypto.randomBytes(1 + crypto.randomInt(0, 80));
            const token = await new CompactEncrypt(plaintext)
                .setProtectedHeader({ alg: setup.alg, enc: encryption.enc, kid: 'key-1', typ: 'example+jwe', 'urn:example:level': 7 })
                .encrypt(keys.encryptKey);
            const { plaintext: decrypted } = await compactDecrypt(token, keys.decryptKey);
            assert(Buffer.from(decrypted).equals(plaintext), 'jose could not decrypt its own JWE');
            compact.push({
                label: `${setup.label} / ${encryption.enc}`,
                algorithm: setup.alg,
                curve: setup.curve ?? null,
                encryption: encryption.enc,
                jwk: JSON.stringify(keys.decryptJwk),
                plaintext: plaintext.toString('hex'),
                token,
            });
        }
    }

    // ECDH-ES with party information, which enters the key derivation.
    const withPartyInfo = [];
    for (const alg of ['ECDH-ES', 'ECDH-ES+A256KW']) {
        const pair = await generateKeyPair(alg, { crv: 'P-256', extractable: true });
        const plaintext = crypto.randomBytes(32);
        const token = await new CompactEncrypt(plaintext)
            .setProtectedHeader({ alg, enc: 'A256GCM' })
            .setKeyManagementParameters({ apu: Buffer.from('Alice'), apv: Buffer.from('Bob') })
            .encrypt(pair.publicKey);
        withPartyInfo.push({ algorithm: alg, jwk: JSON.stringify(await exportJWK(pair.privateKey)), plaintext: plaintext.toString('hex'), token });
    }

    // Flattened JSON with additional authenticated data and all three kinds of header.
    const secret = crypto.createSecretKey(crypto.randomBytes(32));
    const aad = Buffer.from('additional authenticated data');
    const flatPlaintext = crypto.randomBytes(48);
    const flattened = await new FlattenedEncrypt(flatPlaintext)
        .setProtectedHeader({ enc: 'A256GCM' })
        .setSharedUnprotectedHeader({ 'urn:example:shared': 'shared' })
        .setUnprotectedHeader({ alg: 'A256KW', kid: 'flat-key' })
        .setAdditionalAuthenticatedData(aad)
        .encrypt(secret);
    await flattenedDecrypt(flattened, secret);

    // General JSON with three recipients using different algorithms.
    const rsa = await generateKeyPair('RSA-OAEP-256', { extractable: true });
    const ec = await generateKeyPair('ECDH-ES+A128KW', { crv: 'P-384', extractable: true });
    const kw = crypto.createSecretKey(crypto.randomBytes(16));
    const generalPlaintext = crypto.randomBytes(64);
    const general = await new GeneralEncrypt(generalPlaintext)
        .setProtectedHeader({ enc: 'A128CBC-HS256' })
        .addRecipient(rsa.publicKey).setUnprotectedHeader({ alg: 'RSA-OAEP-256', kid: 'rsa' })
        .addRecipient(ec.publicKey).setUnprotectedHeader({ alg: 'ECDH-ES+A128KW', kid: 'ec' })
        .addRecipient(kw).setUnprotectedHeader({ alg: 'A128KW', kid: 'kw' })
        .encrypt();
    for (const key of [rsa.privateKey, ec.privateKey, kw]) {
        await generalDecrypt(general, key);
    }

    write('valid.json', 'JWEs encrypted by jose for every key management and content encryption algorithm.', {
        compact,
        withPartyInfo,
        flattened: {
            json: JSON.stringify(flattened),
            jwk: JSON.stringify(await exportJWK(secret)),
            plaintext: flatPlaintext.toString('hex'),
            aad: aad.toString('hex'),
        },
        general: {
            json: JSON.stringify(general),
            plaintext: generalPlaintext.toString('hex'),
            recipients: [
                { algorithm: 'RSA-OAEP-256', keyID: 'rsa', jwk: JSON.stringify(await exportJWK(rsa.privateKey)) },
                { algorithm: 'ECDH-ES+A128KW', keyID: 'ec', jwk: JSON.stringify(await exportJWK(ec.privateKey)) },
                { algorithm: 'A128KW', keyID: 'kw', jwk: JSON.stringify(await exportJWK(kw)) },
            ],
        },
    });
}

async function invalidFixture() {
    const secret = crypto.createSecretKey(crypto.randomBytes(32));
    const other = crypto.createSecretKey(crypto.randomBytes(32));
    const plaintext = Buffer.from('attack at dawn', 'utf8');
    const encode = (value) => base64url.encode(typeof value === 'string' ? value : JSON.stringify(value));

    const good = await new CompactEncrypt(plaintext).setProtectedHeader({ alg: 'A256KW', enc: 'A256GCM' }).encrypt(secret);
    const [header, key, iv, ciphertext, tag] = good.split('.');
    const flip = (segment) => base64url.encode(flipLastBit(Buffer.from(base64url.decode(segment))));
    const cbc = await new CompactEncrypt(plaintext).setProtectedHeader({ alg: 'A256KW', enc: 'A128CBC-HS256' }).encrypt(secret);
    const cbcParts = cbc.split('.');

    // Encrypts with an arbitrary protected header, using the real key, so that only the
    // header's content is at issue.
    const withHeader = async (object) => new CompactEncrypt(plaintext).setProtectedHeader(object).encrypt(secret);
    const direct = await new CompactEncrypt(plaintext).setProtectedHeader({ alg: 'dir', enc: 'A256GCM' }).encrypt(secret);
    const directParts = direct.split('.');

    const candidates = {
        'valid A256KW / A256GCM (positive control)': { token: good },
        'valid A256KW / A128CBC-HS256': { token: cbc },
        'valid dir / A256GCM': { token: direct, algorithm: 'dir' },
        'wrong key': { token: good, wrongKey: true },
        'ciphertext altered': { token: [header, key, iv, flip(ciphertext), tag].join('.') },
        'tag altered': { token: [header, key, iv, ciphertext, flip(tag)].join('.') },
        'iv altered': { token: [header, key, flip(iv), ciphertext, tag].join('.') },
        'encrypted key altered': { token: [header, flip(key), iv, ciphertext, tag].join('.') },
        'header altered (typ added)': { token: [encode({ alg: 'A256KW', enc: 'A256GCM', typ: 'x' }), key, iv, ciphertext, tag].join('.') },
        'CBC ciphertext altered': { token: [cbcParts[0], cbcParts[1], cbcParts[2], flip(cbcParts[3]), cbcParts[4]].join('.') },
        'CBC tag altered': { token: [cbcParts[0], cbcParts[1], cbcParts[2], cbcParts[3], flip(cbcParts[4])].join('.') },
        'CBC ciphertext truncated by a block': { token: [cbcParts[0], cbcParts[1], cbcParts[2], base64url.encode(Buffer.from(base64url.decode(cbcParts[3])).subarray(16)), cbcParts[4]].join('.') },
        'tag truncated': { token: [header, key, iv, ciphertext, base64url.encode(Buffer.from(base64url.decode(tag)).subarray(0, 12))].join('.') },
        'tag empty': { token: [header, key, iv, ciphertext, ''].join('.') },
        'iv too short': { token: [header, key, base64url.encode(Buffer.from(base64url.decode(iv)).subarray(0, 8)), ciphertext, tag].join('.') },
        'iv empty': { token: [header, key, '', ciphertext, tag].join('.') },
        'encrypted key empty': { token: [header, '', iv, ciphertext, tag].join('.') },
        'ciphertext empty': { token: [header, key, iv, '', tag].join('.') },
        'four segments': { token: [header, key, iv, ciphertext].join('.') },
        'six segments': { token: `${good}.extra` },
        'three segments (a JWS shape)': { token: [header, key, iv].join('.') },
        'empty string': { token: '' },
        'header empty': { token: ['', key, iv, ciphertext, tag].join('.') },
        'header is not JSON': { token: [encode('not json'), key, iv, ciphertext, tag].join('.') },
        'header is a JSON array': { token: [encode('["alg"]'), key, iv, ciphertext, tag].join('.') },
        'header has duplicate alg': { token: [encode('{"alg":"A256KW","alg":"dir","enc":"A256GCM"}'), key, iv, ciphertext, tag].join('.') },
        'alg missing': { token: [encode({ enc: 'A256GCM' }), key, iv, ciphertext, tag].join('.') },
        'enc missing': { token: [encode({ alg: 'A256KW' }), key, iv, ciphertext, tag].join('.') },
        'alg is a number': { token: [encode({ alg: 1, enc: 'A256GCM' }), key, iv, ciphertext, tag].join('.') },
        'alg unknown': { token: [encode({ alg: 'A999KW', enc: 'A256GCM' }), key, iv, ciphertext, tag].join('.') },
        'alg none': { token: [encode({ alg: 'none', enc: 'A256GCM' }), key, iv, ciphertext, tag].join('.') },
        'alg changed to dir with the wrapping key': { token: [encode({ alg: 'dir', enc: 'A256GCM' }), key, iv, ciphertext, tag].join('.') },
        'enc unknown': { token: [encode({ alg: 'A256KW', enc: 'A999GCM' }), key, iv, ciphertext, tag].join('.') },
        'enc changed to A128GCM': { token: [encode({ alg: 'A256KW', enc: 'A128GCM' }), key, iv, ciphertext, tag].join('.') },
        'dir with a non-empty encrypted key': { token: [directParts[0], key, directParts[2], directParts[3], directParts[4]].join('.'), algorithm: 'dir' },
        'zip DEF': { token: [encode({ alg: 'A256KW', enc: 'A256GCM', zip: 'DEF' }), key, iv, ciphertext, tag].join('.') },
        // jose has to be told the extension is understood in order to write it at all.
        'crit names an unknown extension': {
            token: await new CompactEncrypt(plaintext)
                .setProtectedHeader({ alg: 'A256KW', enc: 'A256GCM', crit: ['urn:example:x'], 'urn:example:x': 1 })
                .encrypt(secret, { crit: { 'urn:example:x': true } }),
        },
        'crit is empty': { token: await withHeader({ alg: 'A256KW', enc: 'A256GCM', crit: [] }).catch(() => [encode({ alg: 'A256KW', enc: 'A256GCM', crit: [] }), key, iv, ciphertext, tag].join('.')) },
        'crit names enc': { token: await withHeader({ alg: 'A256KW', enc: 'A256GCM', crit: ['enc'] }).catch(() => [encode({ alg: 'A256KW', enc: 'A256GCM', crit: ['enc'] }), key, iv, ciphertext, tag].join('.')) },
        'header segment padded': { token: [`${header}=`, key, iv, ciphertext, tag].join('.') },
        'tag segment padded': { token: [header, key, iv, ciphertext, `${tag}==`].join('.') },
        'trailing newline': { token: `${good}\n` },
        'unknown non-critical parameter': { token: await withHeader({ alg: 'A256KW', enc: 'A256GCM', 'urn:example:ignored': [1, 2] }) },
        'kid is a number': { token: await withHeader({ alg: 'A256KW', enc: 'A256GCM', kid: 5 }) },
    };

    const cases = [];
    for (const [name, candidate] of Object.entries(candidates)) {
        let jose;
        try {
            const result = await compactDecrypt(candidate.token, candidate.wrongKey ? other : secret);
            jose = { accepted: true, plaintext: Buffer.from(result.plaintext).toString('hex') };
        } catch (error) {
            jose = { accepted: false, error: `${error.code ?? error.name}: ${error.message}` };
        }
        cases.push({ name, token: candidate.token, wrongKey: candidate.wrongKey ?? false, jose });
    }
    assert(cases[0].jose.accepted, 'positive control was rejected by jose');

    write('compact-decryption.json', 'Compact JWEs, valid and not, with jose compactDecrypt\'s verdict under one 256-bit key.', {
        jwk: JSON.stringify(await exportJWK(secret)),
        wrongJwk: JSON.stringify(await exportJWK(other)),
        cases,
    });
}

await validFixture();
await invalidFixture();
