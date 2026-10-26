// Closed-loop interoperability check. The counterpart (OpenSSL through Node, and jose for
// thumbprints) sets a challenge, the Swift package answers it, and the counterpart judges the
// answers.
//
//     node secp256k1/closed-loop.mjs challenge <challenge.json>
//     swift run jose-secp256k1-interop < challenge.json > response.json
//     node secp256k1/closed-loop.mjs verify <challenge.json> <response.json>
//
// `scripts/interop.sh` runs all three. `verify` exits non-zero on any disagreement.

import crypto from 'node:crypto';
import fs from 'node:fs';
import { base64url, calculateJwkThumbprint } from 'jose';
import { runClosedLoop } from '../shared/closed-loop.mjs';
import { flipLastBit } from '../shared/fixtures.mjs';
import {
    ORDER, compact, exportJwk, generateKeyPair, isLowS, otherForm, sign, signingInput, verifies, withS,
} from './common.mjs';

async function challenge(file) {
    // Keys for the Swift side to sign with.
    const signingKeys = [];
    for (let i = 0; i < 3; i++) {
        signingKeys.push(JSON.stringify(exportJwk(generateKeyPair().privateKey)));
    }

    // JWSs for the Swift side to judge. `expected` is OpenSSL's verdict; the Swift program does not
    // read it.
    const verify = [];
    for (let i = 0; i < 8; i++) {
        const { publicKey, privateKey } = generateKeyPair();
        const other = generateKeyPair().publicKey;
        const payload = crypto.randomBytes(1 + i * 25);
        const input = signingInput({ alg: 'ES256K' }, payload);
        const signature = sign(privateKey, input);
        const variants = [
            { signature },
            { signature: otherForm(signature) },
            { signature: flipLastBit(signature) },
            { signature: withS(signature, ORDER) },
            { signature, key: other },
        ];
        for (const variant of variants) {
            const key = variant.key ?? publicKey;
            verify.push({
                jwk: JSON.stringify(exportJwk(key)),
                token: compact(input, variant.signature),
                expected: verifies(key, input, variant.signature)
                    ? { accepted: true, payload: payload.toString('hex') }
                    : { accepted: false },
            });
        }
    }

    fs.writeFileSync(file, JSON.stringify({ payload: crypto.randomBytes(100).toString('hex'), signingKeys, verify }));
}

async function verify(challenge, response, { check, count }) {
    /** OpenSSL's verdict on a compact ES256K JWS, and whether its signature has a low S. */
    function judge(token, publicKey) {
        const [header, body, signature] = token.split('.');
        const bytes = Buffer.from(base64url.decode(signature));
        return {
            alg: JSON.parse(Buffer.from(base64url.decode(header)).toString('utf8')).alg,
            payload: Buffer.from(base64url.decode(body)).toString('hex'),
            accepted: verifies(publicKey, `${header}.${body}`, bytes),
            lowS: bytes.length === 64 && isLowS(bytes),
            tamperedAccepted: verifies(publicKey, `${header}.${body}`, flipLastBit(bytes)),
        };
    }

    // Tokens signed with the counterpart's keys.
    check('signed count', '', response.signed.length === challenge.signingKeys.length, `${response.signed.length}`);
    for (const [index, token] of response.signed.entries()) {
        const label = `[${index}]`;
        const publicKey = crypto.createPublicKey(crypto.createPrivateKey({ key: JSON.parse(challenge.signingKeys[index]), format: 'jwk' }));
        const verdict = judge(token, publicKey);
        check('signed with counterpart key accepted', label, verdict.accepted && verdict.payload === challenge.payload, JSON.stringify(verdict));
        check('signed with counterpart key has alg ES256K', label, verdict.alg === 'ES256K', verdict.alg);
        check('signed with counterpart key has low S', label, verdict.lowS, '');
        check('signed with counterpart key refused once altered', label, !verdict.tamperedAccepted, '');
    }

    // Keys the Swift side generated, as JWKs, with a token signed by each.
    check('generated count', '', response.generated.length >= 3, `${response.generated.length}`);
    for (const [index, item] of response.generated.entries()) {
        const label = `[${index}]`;
        const privateJwk = JSON.parse(item.privateJwk);
        const publicJwk = JSON.parse(item.publicJwk);
        let privateKey;
        let publicKey;
        try {
            privateKey = crypto.createPrivateKey({ key: privateJwk, format: 'jwk' });
            publicKey = crypto.createPublicKey({ key: publicJwk, format: 'jwk' });
        } catch (error) {
            check('generated JWKs import', label, false, `${error.code}: ${error.message}`);
            continue;
        }
        check('generated JWKs import', label, true, '');
        const derived = exportJwk(crypto.createPublicKey(privateKey));
        check('generated private key matches its public key', label, derived.x === publicJwk.x && derived.y === publicJwk.y && publicJwk.crv === 'secp256k1', JSON.stringify(publicJwk));
        check('generated public JWK has no private member', label, !('d' in publicJwk), '');
        check('generated private JWK has kid', label, privateJwk.kid === item.keyID && publicJwk.kid === item.keyID, `${privateJwk.kid} ${publicJwk.kid}`);
        check('generated thumbprint matches jose', label, item.thumbprint === (await calculateJwkThumbprint(publicJwk, 'sha256')), item.thumbprint);
        const verdict = judge(item.token, publicKey);
        check('signed with generated key accepted', label, verdict.accepted && verdict.payload === challenge.payload, JSON.stringify(verdict));
        check('signed with generated key has low S', label, verdict.lowS, '');
        // The counterpart's own signature with the generated key must verify too, which checks
        // the key itself rather than only the Swift side's consistency with it.
        const input = item.token.split('.').slice(0, 2).join('.');
        check('counterpart signature with generated key accepted', label, verifies(publicKey, input, sign(privateKey, input)), '');
    }

    check('verdict count', '', response.verdicts.length === challenge.verify.length, `${response.verdicts.length}`);
    for (const [index, item] of challenge.verify.entries()) {
        const verdict = response.verdicts[index] ?? {};
        const label = `[${index}]`;
        if (item.expected.accepted) {
            check('Swift accepts valid OpenSSL JWS', label, verdict.accepted === true && verdict.payload === item.expected.payload, JSON.stringify(verdict));
        } else {
            check('Swift rejects invalid OpenSSL JWS', label, verdict.accepted === false, JSON.stringify(verdict));
        }
    }
    check('challenge has both verdicts', '', count('Swift accepts valid OpenSSL JWS') > 0 && count('Swift rejects invalid OpenSSL JWS') > 0, '');
}

await runClosedLoop({ challenge, verify });
