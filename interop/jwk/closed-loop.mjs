// Closed-loop interoperability check. The counterpart sets a challenge, the Swift package
// answers it, and the counterpart judges the answers.
//
//     node closed-loop.mjs challenge <challenge.json>
//     swift run jose-jwk-interop < challenge.json > response.json
//     node closed-loop.mjs verify <challenge.json> <response.json>
//
// `scripts/interop.sh` runs all three. `verify` exits non-zero on any disagreement.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { calculateJwkThumbprint, calculateJwkThumbprintUri, exportJWK, generateKeyPair, importJWK } from 'jose';
import { ASYMMETRIC, HMAC, RSA, hmac, kindForCurve, rsaSign, rsaSpec, rsaVerifies, sign, verifies } from '../shared/algorithms.mjs';
import { runClosedLoop } from '../shared/closed-loop.mjs';
import { flipLastBit } from '../shared/fixtures.mjs';

const HASHES = ['sha256', 'sha384', 'sha512'];

async function challenge(file) {
    const messages = [Buffer.alloc(0), crypto.randomBytes(1), crypto.randomBytes(32), crypto.randomBytes(500)];

    const hmacCases = [];
    for (const spec of HMAC) {
        for (let i = 0; i < 5; i++) {
            const key = crypto.randomBytes(spec.byteCount + i * 7);
            hmacCases.push({
                algorithm: spec.alg,
                jwk: JSON.stringify(await exportJWK(crypto.createSecretKey(key))),
                key: key.toString('hex'),
                message: crypto.randomBytes(64).toString('hex'),
            });
        }
    }

    // Signatures for the Swift side to judge. `expected` is the counterpart's own verdict; the
    // Swift program does not read it.
    const verify = [];
    for (const kind of ASYMMETRIC) {
        const pair = await generateKeyPair(kind.joseAlg, { extractable: true });
        const other = await generateKeyPair(kind.joseAlg, { extractable: true });
        const jwk = JSON.stringify(await exportJWK(pair.publicKey));
        const otherJwk = JSON.stringify(await exportJWK(other.publicKey));
        for (const algorithm of kind.algs) {
            for (let i = 0; i < 20; i++) {
                const message = crypto.randomBytes(48);
                const signature = await sign(kind, pair.privateKey, message);
                const variants = [
                    { jwk, message, signature },
                    { jwk, message, signature: flipLastBit(signature) },
                    { jwk, message: flipLastBit(message), signature },
                    { jwk: otherJwk, message, signature },
                ];
                for (const variant of variants) {
                    const publicKey = variant.jwk === jwk ? pair.publicKey : other.publicKey;
                    verify.push({
                        algorithm,
                        curve: kind.name,
                        jwk: variant.jwk,
                        message: variant.message.toString('hex'),
                        signature: variant.signature.toString('hex'),
                        expected: await verifies(kind, publicKey, variant.message, variant.signature),
                    });
                }
            }
        }
    }

    {
        const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
        const jwk = JSON.stringify(await exportJWK(pair.publicKey));
        const otherJwk = JSON.stringify(await exportJWK(other.publicKey));
        for (const spec of RSA) {
            for (let i = 0; i < 5; i++) {
                const message = crypto.randomBytes(48);
                const signature = rsaSign(spec, pair.privateKey, message);
                // The last variant is a signature made under a different RSA algorithm.
                const otherSpec = RSA[(RSA.indexOf(spec) + 3) % RSA.length];
                const variants = [
                    { jwk, key: pair.publicKey, message, signature },
                    { jwk, key: pair.publicKey, message, signature: flipLastBit(signature) },
                    { jwk, key: pair.publicKey, message: flipLastBit(message), signature },
                    { jwk: otherJwk, key: other.publicKey, message, signature },
                    { jwk, key: pair.publicKey, message, signature: rsaSign(otherSpec, pair.privateKey, message) },
                ];
                for (const variant of variants) {
                    verify.push({
                        algorithm: spec.alg,
                        curve: 'RSA',
                        jwk: variant.jwk,
                        message: variant.message.toString('hex'),
                        signature: variant.signature.toString('hex'),
                        expected: rsaVerifies(spec, variant.key, variant.message, variant.signature),
                    });
                }
            }
        }
    }

    fs.writeFileSync(file, JSON.stringify({ messages: messages.map((m) => m.toString('hex')), hmac: hmacCases, verify }));
}

async function verify(challenge, response, { check }) {
    for (const [index, key] of response.keys.entries()) {
        const isRSA = key.curve === 'RSA';
        const kind = isRSA ? { joseAlg: 'RS256', algs: RSA.map((spec) => spec.alg) } : kindForCurve(key.curve);
        const label = `key[${index}] ${key.curve}`;
        const publicJwk = JSON.parse(key.publicJwk);
        // RSA goes through Node's crypto with a KeyObject, because a WebCrypto RSA key is bound
        // to one algorithm and these keys are used under six.
        const verifyWith = (algorithm, verifyKey, message, signature) =>
            isRSA
                ? rsaVerifies(rsaSpec(algorithm), crypto.createPublicKey({ key: publicJwk, format: 'jwk' }), message, signature)
                : verifies(kind, verifyKey, message, signature);

        let publicKey;
        try {
            publicKey = await importJWK(publicJwk, kind.joseAlg);
        } catch (error) {
            check('public JWK import', label, false, `jose rejected ${key.publicJwk}: ${error.message}`);
            continue;
        }
        check('public JWK import', label, publicKey.type === 'public', `imported as ${publicKey.type}`);
        check('public JWK has no private member', label, !('d' in publicJwk), 'd present');

        if (key.privateJwk) {
            try {
                const privateKey = await importJWK(JSON.parse(key.privateJwk), kind.joseAlg, { extractable: true });
                const reexported = await exportJWK(privateKey);
                check('private JWK import', label, privateKey.type === 'private', `imported as ${privateKey.type}`);
                check(
                    'private JWK matches public',
                    label,
                    reexported.x === publicJwk.x && reexported.y === publicJwk.y && reexported.n === publicJwk.n && reexported.e === publicJwk.e,
                    'public members differ',
                );
                // The counterpart signs with the Swift-made private key and verifies with the
                // Swift-made public key.
                const message = crypto.randomBytes(32);
                const signature = isRSA
                    ? rsaSign(rsaSpec('PS256'), crypto.createPrivateKey({ key: JSON.parse(key.privateJwk), format: 'jwk' }), message)
                    : await sign(kind, privateKey, message);
                check(
                    'private JWK signs for public JWK',
                    label,
                    await verifyWith('PS256', publicKey, message, signature),
                    'signature did not verify',
                );
            } catch (error) {
                check('private JWK import', label, false, `jose rejected the private JWK: ${error.message}`);
            }
        }

        for (const hash of HASHES) {
            const expected = await calculateJwkThumbprint(publicJwk, hash);
            check('thumbprint', `${label} ${hash}`, key.thumbprints[hash] === expected, `Swift ${key.thumbprints[hash]}, jose ${expected}`);
            const expectedUri = await calculateJwkThumbprintUri(publicJwk, hash);
            check('thumbprint URI', `${label} ${hash}`, key.thumbprintUris[hash] === expectedUri, `Swift ${key.thumbprintUris[hash]}, jose ${expectedUri}`);
        }

        const expectedSignatures = challenge.messages.length * kind.algs.length;
        // A Secure Enclave key signs under ES256 only, which is all P-256 has anyway.
        check('signature count', label, key.signatures.length === expectedSignatures, `${key.signatures.length} signatures`);
        for (const [i, item] of key.signatures.entries()) {
            const message = Buffer.from(item.message, 'hex');
            const signature = Buffer.from(item.signature, 'hex');
            check('signature algorithm', `${label}[${i}]`, kind.algs.includes(item.algorithm), item.algorithm);
            check('signature message', `${label}[${i}]`, challenge.messages.includes(item.message), 'not a challenge message');
            check('signature accepted', `${label}[${i}]`, await verifyWith(item.algorithm, publicKey, message, signature), 'counterpart rejected it');
            // Shows that acceptance above is not vacuous.
            check(
                'tampered signature refused',
                `${label}[${i}]`,
                !(await verifyWith(item.algorithm, publicKey, message, flipLastBit(signature))),
                'counterpart accepted a tampered signature',
            );
        }
    }
    check('RSA keys present', '', response.keys.filter((key) => key.curve === 'RSA').length === 2, '');
    check('key count', '', response.keys.length >= 14, `${response.keys.length} keys`);

    check('hmac count', '', response.hmac.length === challenge.hmac.length, `${response.hmac.length} tags`);
    for (const [index, item] of challenge.hmac.entries()) {
        const spec = HMAC.find((candidate) => candidate.alg === item.algorithm);
        const expected = hmac(spec, Buffer.from(item.key, 'hex'), Buffer.from(item.message, 'hex')).toString('hex');
        check('hmac tag', `[${index}] ${item.algorithm}`, response.hmac[index] === expected, `Swift ${response.hmac[index]}, counterpart ${expected}`);
    }

    check('verdict count', '', response.verdicts.length === challenge.verify.length, `${response.verdicts.length} verdicts`);
    let expectedAccepts = 0;
    let expectedRejects = 0;
    for (const [index, item] of challenge.verify.entries()) {
        if (item.expected) expectedAccepts += 1;
        else expectedRejects += 1;
        check(
            item.expected ? 'Swift accepts valid counterpart signature' : 'Swift rejects invalid counterpart signature',
            `[${index}] ${item.algorithm}`,
            response.verdicts[index] === item.expected,
            `Swift said ${response.verdicts[index]}`,
        );
    }
    check('challenge has both verdicts', '', expectedAccepts > 0 && expectedRejects > 0, `${expectedAccepts}/${expectedRejects}`);
    console.log(`Secure Enclave key included: ${response.usedSecureEnclave ? 'yes' : 'no'}`);
}

await runClosedLoop({ challenge, verify });
