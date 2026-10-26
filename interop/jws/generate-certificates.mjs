// Generates the certificate fixture in Tests/JOSEJWSTests/Fixtures/certificates.json with
// OpenSSL, for the x5c key-resolution tests.
//
//     cd interop && node jws/generate-certificates.mjs
//
// A private CA signs two leaf certificates (one P-256, one RSA); a second CA exists so that a
// chain ending at the wrong anchor can be checked; one leaf is already expired. Keys and
// certificates are random on every run.

import crypto from 'node:crypto';
import { exportJWK } from 'jose';
import { fixtureWriter } from '../shared/fixtures.mjs';
import { PKI } from '../shared/pki.mjs';

const write = fixtureWriter(import.meta.url, 'JOSEJWSTests');
const pki = new PKI();

const root = pki.root('root');
const otherRoot = pki.root('other-root');
const ec = pki.issue('ec-leaf', root);
const rsa = pki.issue('rsa-leaf', root, { keyType: 'rsa' });
const expired = pki.issue('expired-leaf', root, { validity: ['20200101000000Z', '20210101000000Z'] });
const underOther = pki.issue('other-leaf', otherRoot);

async function entry(leaf) {
    return {
        der: leaf.der.toString('hex'),
        privateJwk: JSON.stringify(await exportJWK(leaf.privateKey)),
        publicJwk: JSON.stringify(await exportJWK(crypto.createPublicKey(leaf.privateKey))),
        sha1: crypto.createHash('sha1').update(leaf.der).digest('base64url'),
        sha256: crypto.createHash('sha256').update(leaf.der).digest('base64url'),
    };
}

write(
    'certificates.json',
    'A private CA, leaf certificates under it (P-256, RSA, one expired) and a leaf under another CA.',
    {
        root: root.der.toString('hex'),
        otherRoot: otherRoot.der.toString('hex'),
        ecLeaf: await entry(ec),
        rsaLeaf: await entry(rsa),
        expiredLeaf: await entry(expired),
        leafUnderOtherRoot: await entry(underOther),
    },
    { opensslCommand: pki.version },
);
pki.remove();
