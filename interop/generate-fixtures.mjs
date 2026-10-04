// Generates the fixtures in Tests/JOSECoreTests/Fixtures by running the counterpart
// implementation: panva/jose and Node's own crypto (OpenSSL).
//
//     cd interop && npm ci && node generate-fixtures.mjs
//
// Every expected value in a fixture is produced by, or confirmed by, the counterpart. Nothing is
// transcribed from a specification. ECDSA fixtures change on every run because signing is
// randomised.

import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createRequire } from 'node:module';
import { base64url } from 'jose';
import { CURVES, generateKeyPair, sign, verifies } from './ecdsa.mjs';

const require = createRequire(import.meta.url);
const joseVersion = require('jose/package.json').version;
const fixturesDirectory = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    '../Tests/JOSECoreTests/Fixtures',
);

function write(name, description, body) {
    const fixture = {
        _generated: {
            notice: 'GENERATED FILE. Do not edit by hand; rerun interop/generate-fixtures.mjs.',
            generator: 'interop/generate-fixtures.mjs',
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

// ---------------------------------------------------------------------------------------------
// base64url
// ---------------------------------------------------------------------------------------------

function base64urlFixture() {
    const inputs = [];
    for (let length = 0; length <= 48; length++) {
        inputs.push(crypto.randomBytes(length));
    }
    // Bytes that exercise the two characters that differ from standard base64, and all-ones.
    inputs.push(Buffer.from([0xfb]), Buffer.from([0xff]), Buffer.from([0xfb, 0xff]));
    inputs.push(Buffer.from([0xfb, 0xff, 0xbf]), Buffer.from([0x00]), Buffer.alloc(32, 0xff));
    inputs.push(crypto.randomBytes(1024));

    const encode = inputs.map((bytes) => {
        const encoded = base64url.encode(bytes);
        assert(encoded === bytes.toString('base64url'), 'jose and Buffer disagree on encoding');
        return { hex: bytes.toString('hex'), base64url: encoded };
    });

    // Inputs to decode. These are only inputs: what happens to each is recorded from jose.
    const candidates = [
        '', 'YQ', 'YWI', 'YWJj', 'Zm9vYg', 'Zm9vYmE', 'Zm9vYmFy', '-_8', '_-8', '__8',
        // correct padding
        'YQ==', 'YWI=', 'Zm9vYg==', 'Zm9vYmE=',
        // wrong amount of padding
        'YQ=', 'YQ===', 'YWI==', 'YWJj=', 'YWJj====', '=', '==', '====',
        // padding somewhere other than the end
        'YQ=a', '=YQ', 'YW=I', 'YQ==YQ', 'YQ==YQ==',
        // 4n+1
        'Y', 'YWJjZ', 'YWJjZGVmZ',
        // non-zero unused bits in the final character
        'YR', 'YX', 'YWJ', 'YWL', 'Zm9vYh',
        // standard alphabet, whitespace, other bytes
        '+/8', 'YW+j', 'YW/j', 'Y Q', ' YQ', 'YQ ', 'YQ\n', 'YQ\r\n', 'YW\tI', 'YQ\u0000', 'YQ.', 'é', 'YWé',
    ];
    const decode = candidates.map((input) => {
        let jose;
        try {
            jose = { accepted: true, hex: Buffer.from(base64url.decode(input)).toString('hex') };
        } catch (error) {
            jose = { accepted: false, error: String(error.message) };
        }
        return { input, jose };
    });

    write('base64url.json', 'base64url encodings from jose, and what jose does with each decode input.', {
        encode,
        decode,
    });
}

// ---------------------------------------------------------------------------------------------
// ECDSA DER <-> P1363
// ---------------------------------------------------------------------------------------------

// Splits a DER ECDSA signature produced by OpenSSL. Only used on well-formed input, and its
// result is never trusted on its own: every pair written to the fixture is checked by having
// OpenSSL verify the DER form as DER and the raw form as P1363, over the same message and key.
function splitDER(der) {
    let offset = 1;
    if (der[offset] & 0x80) {
        offset += 1 + (der[offset] & 0x7f);
    } else {
        offset += 1;
    }
    const integers = [];
    for (let i = 0; i < 2; i++) {
        const length = der[offset + 1];
        integers.push(der.subarray(offset + 2, offset + 2 + length));
        offset += 2 + length;
    }
    return integers;
}

function describe(der, curve) {
    const integers = splitDER(der);
    const magnitudes = integers.map((integer) => (integer[0] === 0 && integer.length > 1 ? integer.subarray(1) : integer));
    const raw = Buffer.concat(
        magnitudes.map((magnitude) =>
            Buffer.concat([Buffer.alloc(curve.coordinateByteCount - magnitude.length), magnitude]),
        ),
    );
    return {
        raw,
        // A DER INTEGER carries a leading 0x00 that the raw form must not.
        hasSignByte: integers.some((integer) => integer[0] === 0 && integer.length > 1),
        // A DER INTEGER is shorter than the coordinate and the raw form must be left-padded.
        hasShortComponent: magnitudes.some((magnitude) => magnitude.length < curve.coordinateByteCount),
    };
}

function ecdsaFixture() {
    const ordinaryPerCurve = 40;
    const shortPerCurve = 8;
    const curves = CURVES.map((curve) => {
        const { privateKey, publicKey } = generateKeyPair(curve);
        const vectors = [];
        let ordinary = 0;
        let short = 0;
        let attempts = 0;
        while (ordinary < ordinaryPerCurve || short < shortPerCurve) {
            attempts += 1;
            assert(attempts < 200000, `could not find enough short components for ${curve.name}`);
            const message = crypto.randomBytes(32);
            const der = sign(curve, privateKey, message, 'der');
            const { raw, hasSignByte, hasShortComponent } = describe(der, curve);
            if (hasShortComponent) {
                if (short >= shortPerCurve) continue;
                short += 1;
            } else {
                if (ordinary >= ordinaryPerCurve) continue;
                ordinary += 1;
            }
            assert(verifies(curve, publicKey, message, der, 'der'), 'OpenSSL rejected its own DER signature');
            assert(verifies(curve, publicKey, message, raw, 'ieee-p1363'), 'OpenSSL rejected the raw form');
            vectors.push({ der: der.toString('hex'), raw: raw.toString('hex'), hasSignByte, hasShortComponent });
        }

        // Malformed DER, each derived from a real signature. `opensslAccepts` is OpenSSL's verdict
        // when asked to verify it over the original message.
        const message = crypto.randomBytes(32);
        let base;
        do {
            base = sign(curve, privateKey, message, 'der');
            // Want r with a sign byte and s without one, so each mutation below is applicable.
            // (On P-521 a sign byte only occurs on a short component, so length is not constrained.)
        } while (splitDER(base)[0][0] !== 0 || splitDER(base)[1][0] === 0);
        assert(verifies(curve, publicKey, message, base, 'der'), 'positive control for malformed DER failed');

        const headerLength = base[1] & 0x80 ? 3 : 2;
        const body = base.subarray(headerLength);
        const [r, s] = splitDER(base);
        const integer = (content) => Buffer.concat([Buffer.from([0x02, content.length]), content]);
        const sequence = (content) =>
            Buffer.concat([
                content.length < 0x80 ? Buffer.from([0x30, content.length]) : Buffer.from([0x30, 0x81, content.length]),
                content,
            ]);
        const malformedCandidates = {
            'empty': Buffer.alloc(0),
            'truncated by one byte': base.subarray(0, base.length - 1),
            'byte appended after the SEQUENCE': Buffer.concat([base, Buffer.from([0x00])]),
            'extra byte inside the SEQUENCE': sequence(Buffer.concat([body, Buffer.from([0x00])])),
            'wrong outer tag': Buffer.concat([Buffer.from([0x31]), base.subarray(1)]),
            'r is not an INTEGER': sequence(Buffer.concat([Buffer.from([0x03]), integer(r).subarray(1), integer(s)])),
            'r missing its sign byte (negative)': sequence(Buffer.concat([integer(r.subarray(1)), integer(s)])),
            's with a redundant leading zero': sequence(
                Buffer.concat([integer(r), integer(Buffer.concat([Buffer.from([0x00]), s]))]),
            ),
            'indefinite SEQUENCE length': Buffer.concat([Buffer.from([0x30, 0x80]), body, Buffer.from([0x00, 0x00])]),
            'zero-length r': sequence(Buffer.concat([integer(Buffer.alloc(0)), integer(s)])),
            'only r present': sequence(integer(r)),
            'third INTEGER present': sequence(Buffer.concat([integer(r), integer(s), integer(Buffer.from([0x01]))])),
        };
        if (headerLength === 2) {
            malformedCandidates['long-form SEQUENCE length below 128'] = Buffer.concat([
                Buffer.from([0x30, 0x81, body.length]),
                body,
            ]);
        } else {
            malformedCandidates['two-octet long-form SEQUENCE length'] = Buffer.concat([
                Buffer.from([0x30, 0x82, 0x00, body.length]),
                body,
            ]);
        }
        const malformed = Object.entries(malformedCandidates).map(([name, der]) => ({
            name,
            der: der.toString('hex'),
            opensslAccepts: verifies(curve, publicKey, message, der, 'der'),
        }));

        return {
            curve: curve.name,
            coordinateByteCount: curve.coordinateByteCount,
            vectors,
            malformedBase: base.toString('hex'),
            malformed,
        };
    });

    write(
        'ecdsa-signatures.json',
        'ECDSA signatures made by OpenSSL in DER, with the P1363 form of the same signature. OpenSSL verified ' +
            'both forms of every pair. Includes malformed DER with OpenSSL\'s verdict on each.',
        { curves },
    );
}

// ---------------------------------------------------------------------------------------------
// JSON string escaping
// ---------------------------------------------------------------------------------------------

function jsonStringFixture() {
    const strings = [
        '', 'plain', 'with "quotes"', 'back\\slash', 'a/b', 'https://example.com/path',
        '","y":"forged', '\\"', 'tab\there', 'line\nbreak', 'cr\rhere', '\b\f',
        '\u007f', '\u0080', '  ', 'é', 'é', '日本語', '😀', '﻿',
    ];
    for (let code = 0; code < 0x20; code++) {
        strings.push(`x${String.fromCharCode(code)}y`);
    }
    // The input is carried as UTF-8 bytes so that reading the fixture does not depend on the
    // very escaping rules under test.
    const cases = strings.map((string) => ({
        utf8Hex: Buffer.from(string, 'utf8').toString('hex'),
        stringified: JSON.stringify(string),
    }));
    write('json-strings.json', 'JSON.stringify output for strings, as used for RFC 7638 canonical JSON.', { cases });
}

base64urlFixture();
ecdsaFixture();
jsonStringFixture();
