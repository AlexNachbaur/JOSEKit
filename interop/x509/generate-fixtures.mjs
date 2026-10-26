// Generates the fixture in Tests/JOSEX509Tests/Fixtures/chains.json with OpenSSL: a small PKI,
// certificate chains built from it, and `openssl verify`'s verdict on each chain.
//
//     cd interop && node x509/generate-fixtures.mjs
//
// Every certificate is made by OpenSSL and every verdict is OpenSSL's own. Keys and certificates
// are random on every run; validity periods and the validation time are fixed, so that verdicts
// do not change as the fixture ages.

import crypto from 'node:crypto';
import { assert, fixtureWriter, flipLastBit } from '../shared/fixtures.mjs';
import { CA_EXTENSIONS, PKI, toPEM } from '../shared/pki.mjs';

const write = fixtureWriter(import.meta.url, 'JOSEX509Tests');
const pki = new PKI();

/** The time chains are validated at: 2030-01-01T00:00:00Z. */
const VALIDATION_TIME = 1893456000;
/** A time inside the expired certificates' validity: 2020-07-01T00:00:00Z. */
const PAST_TIME = 1593561600;

/** `openssl verify`'s verdict on `chain` (signer first), trusting only `anchors`. */
function opensslVerdict(chain, anchors, validationTime) {
    pki.writeFile('verify-anchors.pem', anchors.map((anchor) => toPEM(anchor.der)).join(''));
    pki.writeFile('verify-leaf.pem', toPEM(chain[0]));
    const args = ['verify', '-attime', String(validationTime), '-CAfile', 'verify-anchors.pem'];
    if (chain.length > 1) {
        pki.writeFile('verify-untrusted.pem', chain.slice(1).map(toPEM).join(''));
        args.push('-untrusted', 'verify-untrusted.pem');
    }
    args.push('verify-leaf.pem');
    try {
        pki.openssl(...args);
        return { accepted: true };
    } catch (error) {
        const output = `${error.stdout ?? ''}${error.stderr ?? ''}`;
        return { accepted: false, error: output.split('\n').find((line) => line.startsWith('error')) ?? output.trim() };
    }
}

const root = pki.root('root');
const otherRoot = pki.root('other-root');
const constrainedRoot = pki.root('constrained-root', ['basicConstraints=critical,CA:TRUE,pathlen:0', 'keyUsage=critical,keyCertSign,cRLSign']);

const intermediate = pki.issue('intermediate', root, { keyType: 'p384', extensions: CA_EXTENSIONS, validity: ['20190101000000Z', '20400101000000Z'] });
const expiredIntermediate = pki.issue('expired-intermediate', root, { extensions: CA_EXTENSIONS, validity: ['20200101000000Z', '20210101000000Z'] });
const notCA = pki.issue('not-a-ca', root, { extensions: ['basicConstraints=critical,CA:FALSE'] });
const noCertSign = pki.issue('no-cert-sign', root, { extensions: ['basicConstraints=critical,CA:TRUE', 'keyUsage=critical,digitalSignature'] });
const underConstrained = pki.issue('under-constrained', constrainedRoot, { extensions: CA_EXTENSIONS });

const ecLeaf = pki.issue('ec-leaf', root);
const rsaLeaf = pki.issue('rsa-leaf', intermediate, { keyType: 'rsa' });
const p521Leaf = pki.issue('p521-leaf', intermediate, { keyType: 'p521' });
const edLeaf = pki.issue('ed25519-leaf', intermediate, { keyType: 'ed25519' });
const signingLeaf = pki.issue('signing-leaf', root, { extensions: ['keyUsage=critical,digitalSignature'] });
const expiredLeaf = pki.issue('expired-leaf', root, { validity: ['20200101000000Z', '20210101000000Z'] });
const futureLeaf = pki.issue('future-leaf', root, { validity: ['20350101000000Z', '20400101000000Z'] });
const otherLeaf = pki.issue('other-leaf', otherRoot);
const leafOfNotCA = pki.issue('leaf-of-not-a-ca', notCA);
const leafOfNoCertSign = pki.issue('leaf-of-no-cert-sign', noCertSign);
const leafOfConstrained = pki.issue('leaf-of-constrained', underConstrained);
const leafOfExpired = pki.issue('leaf-of-expired-intermediate', expiredIntermediate);
const unknownCritical = pki.issue('unknown-critical-leaf', root, { extensions: ['1.3.6.1.4.1.55555.1=critical,DER:05:00'] });
const encipherOnly = pki.issue('encipherment-leaf', root, { extensions: ['keyUsage=critical,keyEncipherment'] });
// A key usage extension holding NULL where its BIT STRING belongs.
const malformedKeyUsage = pki.issue('malformed-key-usage-leaf', root, { extensions: ['2.5.29.15=critical,DER:05:00'] });
const secp256k1Leaf = pki.issue('secp256k1-leaf', root, { keyType: 'secp256k1' });

const cases = [];
function addCase(name, chain, anchors, { leaf = chain[0], validationTime = VALIDATION_TIME } = {}) {
    const ders = chain.map((certificate) => (Buffer.isBuffer(certificate) ? certificate : certificate.der));
    cases.push({
        name,
        anchors: anchors.map((anchor) => anchor.name),
        chain: ders.map((bytes) => bytes.toString('hex')),
        validationTime,
        publicJwk: JSON.stringify(crypto.createPublicKey(leaf.privateKey).export({ format: 'jwk' })),
        privateJwk: JSON.stringify(leaf.privateKey.export({ format: 'jwk' })),
        openssl: opensslVerdict(ders, anchors, validationTime),
    });
}

addCase('P-256 leaf under the root', [ecLeaf], [root]);
addCase('P-256 leaf with the root in the chain', [ecLeaf, root], [root]);
addCase('RSA leaf under an intermediate', [rsaLeaf, intermediate], [root]);
addCase('P-521 leaf under an intermediate', [p521Leaf, intermediate], [root]);
addCase('Ed25519 leaf under an intermediate', [edLeaf, intermediate], [root]);
addCase('leaf with digitalSignature key usage', [signingLeaf], [root]);
addCase('unrelated certificate after the chain', [rsaLeaf, intermediate, otherRoot], [root]);
addCase('either of two anchors', [otherLeaf], [root, otherRoot]);
addCase('leaf under another root', [otherLeaf], [root]);
addCase('leaf under another root, with that root in the chain', [otherLeaf, otherRoot], [root]);
addCase('intermediate missing', [rsaLeaf], [root]);
addCase('expired leaf', [expiredLeaf], [root]);
addCase('expired leaf, validated during its validity', [expiredLeaf], [root], { validationTime: PAST_TIME });
addCase('leaf not yet valid', [futureLeaf], [root]);
addCase('expired intermediate', [leafOfExpired, expiredIntermediate], [root]);
addCase('issuer is not a CA', [leafOfNotCA, notCA], [root]);
addCase('issuer may not sign certificates', [leafOfNoCertSign, noCertSign], [root]);
addCase('path length exceeded', [leafOfConstrained, underConstrained], [constrainedRoot]);
addCase('leaf signature altered', [flipLastBit(ecLeaf.der)], [root], { leaf: ecLeaf });
addCase('unknown critical extension', [unknownCritical], [root]);
addCase('leaf key usage without digitalSignature', [encipherOnly], [root]);
addCase('malformed key usage', [malformedKeyUsage], [root]);
addCase('secp256k1 leaf', [secp256k1Leaf], [root]);

assert(cases[0].openssl.accepted, 'the positive control verifies');
assert(cases.some((c) => !c.openssl.accepted), 'some chains are refused');

write(
    'chains.json',
    "Certificate chains made by OpenSSL, with `openssl verify`'s verdict on each.",
    {
        anchors: {
            [root.name]: root.der.toString('hex'),
            [otherRoot.name]: otherRoot.der.toString('hex'),
            [constrainedRoot.name]: constrainedRoot.der.toString('hex'),
        },
        cases,
    },
    { opensslCommand: pki.version },
);
pki.remove();
