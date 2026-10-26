// Closed-loop interoperability check. The counterpart sets a challenge, the Swift package
// answers it, and the counterpart judges the answers.
//
//     node closed-loop.mjs challenge <challenge.json>
//     swift run jose-core-interop < challenge.json > response.json
//     node closed-loop.mjs verify <challenge.json> <response.json>
//
// `scripts/interop.sh` runs all three. `verify` exits non-zero on any disagreement.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { base64url } from 'jose';
import { runClosedLoop } from '../shared/closed-loop.mjs';
import { flipLastBit } from '../shared/fixtures.mjs';
import { CURVES, generateKeyPair, publicKeyFromSPKIHex, publicKeyToSPKIHex, sign, verifies } from './ecdsa.mjs';

const SIGNATURES_PER_CURVE = 300;

function challenge(file) {
    const bytesToEncode = [];
    for (let length = 0; length <= 64; length++) {
        bytesToEncode.push(crypto.randomBytes(length).toString('hex'));
    }
    const stringsToDecode = [];
    for (let length = 0; length <= 64; length++) {
        stringsToDecode.push(base64url.encode(crypto.randomBytes(length)));
    }
    const stringsToQuote = ['', 'plain', '","y":"forged', 'a"b\\c/d', '\u0000\u001f\b\f\n\r\t', 'é日本語😀', ' '];
    for (let i = 0; i < 50; i++) {
        // Random strings over a range that includes controls, quotes and backslashes.
        const length = crypto.randomInt(0, 20);
        let string = '';
        for (let j = 0; j < length; j++) {
            string += String.fromCharCode(crypto.randomInt(0, 0x250));
        }
        stringsToQuote.push(string);
    }

    const derSignatures = [];
    const rawSignatures = [];
    for (const curve of CURVES) {
        const { privateKey, publicKey } = generateKeyPair(curve);
        const spki = publicKeyToSPKIHex(publicKey);
        for (let i = 0; i < SIGNATURES_PER_CURVE; i++) {
            for (const [list, encoding] of [[derSignatures, 'der'], [rawSignatures, 'ieee-p1363']]) {
                const message = crypto.randomBytes(32);
                list.push({
                    curve: curve.name,
                    coordinateByteCount: curve.coordinateByteCount,
                    publicKey: spki,
                    message: message.toString('hex'),
                    signature: sign(curve, privateKey, message, encoding).toString('hex'),
                });
            }
        }
    }

    fs.writeFileSync(
        file,
        JSON.stringify({ bytesToEncode, stringsToDecode, stringsToQuote, derSignatures, rawSignatures }),
    );
}

function verify(challenge, response, { check, fail }) {
    function sameLength(section, expected, actual) {
        if (expected.length !== actual?.length) {
            fail(`${section}: expected ${expected.length} answers, got ${actual?.length}`);
            return false;
        }
        return true;
    }

    if (sameLength('encoded', challenge.bytesToEncode, response.encoded)) {
        challenge.bytesToEncode.forEach((hex, i) => {
            const expected = base64url.encode(Buffer.from(hex, 'hex'));
            check('encoded', i, response.encoded[i] === expected, `Swift ${response.encoded[i]}, jose ${expected}`);
        });
    }

    if (sameLength('decoded', challenge.stringsToDecode, response.decoded)) {
        challenge.stringsToDecode.forEach((string, i) => {
            const expected = Buffer.from(base64url.decode(string)).toString('hex');
            check('decoded', i, response.decoded[i] === expected, `Swift ${response.decoded[i]}, jose ${expected}`);
        });
    }

    if (sameLength('quoted', challenge.stringsToQuote, response.quoted)) {
        challenge.stringsToQuote.forEach((string, i) => {
            const expected = JSON.stringify(string);
            check('quoted', i, response.quoted[i] === expected, `Swift ${response.quoted[i]}, JSON.stringify ${expected}`);
        });
    }

    // For each conversion: OpenSSL must accept Swift's output in the target encoding, and must
    // refuse it once a single bit is flipped. The second half shows the first is not vacuous.
    function checkSignatures(section, cases, answers, encoding) {
        if (!sameLength(section, cases, answers)) {
            return;
        }
        cases.forEach((item, i) => {
            const curve = CURVES.find((candidate) => candidate.name === item.curve);
            const publicKey = publicKeyFromSPKIHex(item.publicKey);
            const message = Buffer.from(item.message, 'hex');
            const converted = Buffer.from(answers[i], 'hex');
            check(section, i, verifies(curve, publicKey, message, converted, encoding), `OpenSSL rejected ${answers[i]}`);
            check(
                `${section} (tampered)`,
                i,
                !verifies(curve, publicKey, message, flipLastBit(converted), encoding),
                'OpenSSL accepted a tampered signature',
            );
        });
    }
    checkSignatures('rawFromDER', challenge.derSignatures, response.rawFromDER, 'ieee-p1363');
    checkSignatures('derFromRaw', challenge.rawSignatures, response.derFromRaw, 'der');
}

await runClosedLoop({ challenge, verify });
