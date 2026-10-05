// Generates the fixtures in Tests/JOSEJWSTests/Fixtures by running the counterpart
// implementation, panva/jose.
//
//     cd interop && npm ci && node generate-fixtures.mjs
//
// Every token is produced by jose, and every verdict on a malformed token is jose's own. Nothing
// is transcribed from a specification. The fixtures change on every run because keys and
// signatures are random.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
    CompactSign, FlattenedSign, GeneralSign, base64url, compactVerify, exportJWK, flattenedVerify, generalVerify,
    generateKeyPair,
} from 'jose';
import { ASYMMETRIC, HMAC, joseVersion } from './common.mjs';

const fixturesDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../Tests/JOSEJWSTests/Fixtures');

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

const encode = (value) => base64url.encode(typeof value === 'string' ? value : JSON.stringify(value));

/** Every signing configuration: asymmetric algorithms with their key pair, HMAC with a secret. */
async function signingSetups() {
    const setups = [];
    for (const kind of ASYMMETRIC) {
        for (const alg of kind.algs) {
            const { publicKey, privateKey } = await generateKeyPair(kind.joseAlg, { extractable: true });
            setups.push({ alg, signKey: privateKey, verifyKey: publicKey, jwk: await exportJWK(publicKey), symmetric: false });
        }
    }
    for (const spec of HMAC) {
        const secret = crypto.createSecretKey(crypto.randomBytes(spec.byteCount));
        setups.push({ alg: spec.alg, signKey: secret, verifyKey: secret, jwk: await exportJWK(secret), symmetric: true });
    }
    return setups;
}

async function validFixture(setups) {
    const tokens = [];
    for (const setup of setups) {
        const payload = crypto.randomBytes(40);
        const protectedHeader = { alg: setup.alg, kid: `${setup.alg}-key`, typ: 'example+jws', 'urn:example:level': 7 };

        const compact = await new CompactSign(payload).setProtectedHeader(protectedHeader).sign(setup.signKey);
        await compactVerify(compact, setup.verifyKey);

        const flattened = await new FlattenedSign(payload)
            .setProtectedHeader({ alg: setup.alg })
            .setUnprotectedHeader({ kid: `${setup.alg}-key`, 'urn:example:note': 'unprotected' })
            .sign(setup.signKey);
        await flattenedVerify(flattened, setup.verifyKey);

        // RFC 7797: unencoded payload, detached.
        const unencodedPayload = Buffer.from('{"amount":"12.50","note":"a.b.c é"}', 'utf8');
        const unencoded = await new FlattenedSign(unencodedPayload)
            .setProtectedHeader({ alg: setup.alg, b64: false, crit: ['b64'] })
            .sign(setup.signKey);
        // jose leaves the payload out of what it returns for b64:false; the caller puts it back.
        assert(unencoded.payload === '', 'jose unexpectedly carried the unencoded payload');
        const { payload: emptyPayload, ...unencodedDetached } = unencoded;
        const unencodedAttached = { ...unencodedDetached, payload: unencodedPayload.toString('utf8') };
        await flattenedVerify(unencodedAttached, setup.verifyKey);

        tokens.push({
            algorithm: setup.alg,
            symmetric: setup.symmetric,
            jwk: JSON.stringify(setup.jwk),
            payload: payload.toString('hex'),
            protectedHeader,
            compact,
            // The same token with its payload removed, to be verified with the payload supplied.
            compactDetached: compact.split('.')[0] + '..' + compact.split('.')[2],
            flattened: JSON.stringify(flattened),
            unencodedPayload: unencodedPayload.toString('hex'),
            unencodedFlattened: JSON.stringify(unencodedAttached),
            unencodedFlattenedDetached: JSON.stringify(unencodedDetached),
        });
    }

    // General serialization with one signature per asymmetric setup.
    const asymmetric = setups.filter((setup) => !setup.symmetric);
    const payload = crypto.randomBytes(64);
    const general = new GeneralSign(payload);
    for (const setup of asymmetric) {
        general.addSignature(setup.signKey).setProtectedHeader({ alg: setup.alg, kid: `${setup.alg}-key` });
    }
    const generalJws = await general.sign();
    for (const setup of asymmetric) {
        await generalVerify(generalJws, setup.verifyKey);
    }

    write('valid.json', 'JWSs signed by jose in every serialization, with the keys that verify them.', {
        tokens,
        general: {
            payload: payload.toString('hex'),
            json: JSON.stringify(generalJws),
            signers: asymmetric.map((setup) => ({ algorithm: setup.alg, jwk: JSON.stringify(setup.jwk) })),
        },
    });
}

async function invalidFixture(setups) {
    const setup = setups.find((candidate) => candidate.alg === 'ES256');
    const other = (await generateKeyPair('ES256', { extractable: true }));
    const hmacSetup = setups.find((candidate) => candidate.alg === 'HS256');
    const payload = Buffer.from('{"sub":"alice"}', 'utf8');

    const good = await new CompactSign(payload).setProtectedHeader({ alg: 'ES256', kid: 'k1' }).sign(setup.signKey);
    const [header, body, signature] = good.split('.');
    const signatureBytes = Buffer.from(base64url.decode(signature));
    const flip = (bytes) => {
        const copy = Buffer.from(bytes);
        copy[copy.length - 1] ^= 0x01;
        return copy;
    };

    // Signs arbitrary header text with the real key, so that only the header's content is at
    // issue, never the signature.
    const signWithHeaderText = (headerText, payloadSegment = body) => {
        const protectedSegment = base64url.encode(headerText);
        const input = Buffer.from(`${protectedSegment}.${payloadSegment}`, 'ascii');
        const sig = crypto.sign('sha256', input, { key: setup.signKey, dsaEncoding: 'ieee-p1363' });
        return `${protectedSegment}.${payloadSegment}.${base64url.encode(sig)}`;
    };
    const signWithHeader = (object) => signWithHeaderText(JSON.stringify(object));

    // An HS256 token keyed with the EC public key's JWK text: the classic algorithm-confusion forgery.
    const confusionHeader = encode({ alg: 'HS256', kid: 'k1' });
    const confusionMac = crypto
        .createHmac('sha256', Buffer.from(JSON.stringify(setup.jwk)))
        .update(`${confusionHeader}.${body}`)
        .digest();

    const candidates = {
        'valid (positive control)': good,
        'valid, signed header with whitespace and reordered members': signWithHeaderText('{ "kid" : "k1",\n "alg" : "ES256" }'),
        'payload altered': `${header}.${encode('{"sub":"mallory"}')}.${signature}`,
        'signature altered': `${header}.${body}.${base64url.encode(flip(signatureBytes))}`,
        'header altered': `${encode({ alg: 'ES256', kid: 'k2' })}.${body}.${signature}`,
        'signature truncated': `${header}.${body}.${base64url.encode(signatureBytes.subarray(0, 63))}`,
        'signature empty': `${header}.${body}.`,
        'signature in DER': `${header}.${body}.${base64url.encode(crypto.sign('sha256', Buffer.from(`${header}.${body}`), setup.signKey))}`,
        'signed by a different key': await new CompactSign(payload).setProtectedHeader({ alg: 'ES256', kid: 'k1' }).sign(other.privateKey),
        'alg none, no signature': `${encode({ alg: 'none' })}.${body}.`,
        'alg none, original signature': `${encode({ alg: 'none' })}.${body}.${signature}`,
        'alg None (mixed case)': `${encode({ alg: 'None' })}.${body}.`,
        'alg HS256 keyed with the public key': `${confusionHeader}.${body}.${base64url.encode(confusionMac)}`,
        'alg es256 (lower case)': signWithHeader({ alg: 'es256' }),
        'alg ES384 with a P-256 signature': signWithHeader({ alg: 'ES384' }),
        'alg missing': signWithHeader({ kid: 'k1' }),
        'alg is a number': signWithHeader({ alg: 256 }),
        'alg is null': signWithHeader({ alg: null }),
        'two segments': `${header}.${body}`,
        'four segments': `${good}.extra`,
        'one segment': header,
        'empty string': '',
        'header empty': `.${body}.${signature}`,
        'header is not JSON': signWithHeaderText('not json'),
        'header is a JSON array': signWithHeaderText('["alg","ES256"]'),
        'header is a JSON string': signWithHeaderText('"ES256"'),
        'header has duplicate alg': signWithHeaderText('{"alg":"ES256","alg":"none"}'),
        'header has duplicate alg, first is none': signWithHeaderText('{"alg":"none","alg":"ES256"}'),
        'header segment padded': `${header}=.${body}.${signature}`,
        'payload segment padded': `${header}.${body}=.${signature}`,
        'signature segment padded': `${header}.${body}.${signature}==`,
        'header segment in standard base64': `${header.replace(/-/g, '+').replace(/_/g, '/')}+.${body}.${signature}`,
        'trailing newline': `${good}\n`,
        'leading space': ` ${good}`,
        'space inside the payload segment': `${header}.${body.slice(0, 4)} ${body.slice(4)}.${signature}`,
        'crit names an unknown extension': signWithHeader({ alg: 'ES256', crit: ['urn:example:unknown'], 'urn:example:unknown': true }),
        'crit is empty': signWithHeader({ alg: 'ES256', crit: [] }),
        'crit is not an array': signWithHeader({ alg: 'ES256', crit: 'b64' }),
        'crit names alg': signWithHeader({ alg: 'ES256', crit: ['alg'] }),
        'crit names a parameter that is absent': signWithHeader({ alg: 'ES256', crit: ['urn:example:absent'] }),
        'crit names b64 but b64 is absent': signWithHeader({ alg: 'ES256', crit: ['b64'] }),
        'b64 false without crit': signWithHeader({ alg: 'ES256', b64: false }),
        'b64 is a string': signWithHeader({ alg: 'ES256', b64: 'false', crit: ['b64'] }),
        'b64 true with crit': signWithHeader({ alg: 'ES256', b64: true, crit: ['b64'] }),
        'kid is a number': signWithHeader({ alg: 'ES256', kid: 5 }),
        'typ is a number': signWithHeader({ alg: 'ES256', typ: 5 }),
        'unknown non-critical parameter': signWithHeader({ alg: 'ES256', 'urn:example:ignored': { a: 1 } }),
    };

    const cases = [];
    for (const [name, token] of Object.entries(candidates)) {
        let jose;
        try {
            const result = await compactVerify(token, setup.verifyKey);
            jose = { accepted: true, payload: Buffer.from(result.payload).toString('hex') };
        } catch (error) {
            jose = { accepted: false, error: `${error.code ?? error.name}: ${error.message}` };
        }
        cases.push({ name, token, jose });
    }
    assert(cases[0].jose.accepted, 'positive control was rejected by jose');

    write('compact-verification.json', 'Compact JWSs, valid and not, with jose compactVerify\'s verdict under one ES256 key.', {
        jwk: JSON.stringify({ ...setup.jwk, kid: 'k1' }),
        hmacJwk: JSON.stringify(hmacSetup.jwk),
        cases,
    });
}

const setups = await signingSetups();
await validFixture(setups);
await invalidFixture(setups);
