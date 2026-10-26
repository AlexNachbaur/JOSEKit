// Generates the fixture in Tests/JOSEX509Tests/Fixtures/chains.json with OpenSSL: a small PKI,
// certificate chains built from it, and `openssl verify`'s verdict on each chain.
//
//     cd interop && node x509/generate-fixtures.mjs
//
// Every certificate is made by OpenSSL and every verdict is OpenSSL's own. Keys and certificates
// are random on every run; validity periods and the validation time are fixed, so that verdicts
// do not change as the fixture ages.

import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const fixturesDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../Tests/JOSEX509Tests/Fixtures');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'jose-x509-'));

/** The time chains are validated at: 2030-01-01T00:00:00Z. */
const VALIDATION_TIME = 1893456000;
/** A time inside the expired certificates' validity: 2020-07-01T00:00:00Z. */
const PAST_TIME = 1593561600;

function openssl(...args) {
    return execFileSync('openssl', args, { cwd: work, stdio: ['ignore', 'pipe', 'pipe'] });
}

function assert(condition, message) {
    if (!condition) {
        throw new Error(`fixture generation self-check failed: ${message}`);
    }
}

const KEYS = {
    p256: ['ecparam', '-name', 'prime256v1', '-genkey', '-noout'],
    p384: ['ecparam', '-name', 'secp384r1', '-genkey', '-noout'],
    p521: ['ecparam', '-name', 'secp521r1', '-genkey', '-noout'],
    secp256k1: ['ecparam', '-name', 'secp256k1', '-genkey', '-noout'],
    rsa: ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
    ed25519: ['genpkey', '-algorithm', 'ed25519'],
};

const CA_EXTENSIONS = ['basicConstraints=critical,CA:TRUE', 'keyUsage=critical,keyCertSign,cRLSign'];
const DEFAULT_VALIDITY = ['20250101000000Z', '20350101000000Z'];

function writeExtensions(name, extensions) {
    const file = `${name}.ext`;
    fs.writeFileSync(path.join(work, file), `[v3]\n${extensions.join('\n')}\n`);
    return file;
}

function der(name) {
    return openssl('x509', '-in', `${name}.pem`, '-outform', 'DER');
}

/** A self-signed CA, valid from 2019 to 2040. */
function makeRoot(name, extensions = CA_EXTENSIONS) {
    openssl(...KEYS.p256, '-out', `${name}.key`);
    openssl('req', '-x509', '-new', '-key', `${name}.key`, '-subj', `/CN=${name}`, '-out', `${name}.pem`,
        '-not_before', '20190101000000Z', '-not_after', '20400101000000Z',
        ...extensions.flatMap((extension) => ['-addext', extension]));
    return { name, der: der(name) };
}

/** A certificate for a new key of `keyType`, issued by `issuer`. */
function issue(name, issuer, { keyType = 'p256', extensions = [], validity = DEFAULT_VALIDITY } = {}) {
    openssl(...KEYS[keyType], '-out', `${name}.key`);
    openssl('req', '-new', '-key', `${name}.key`, '-subj', `/CN=${name}`, '-out', `${name}.csr`);
    const args = ['x509', '-req', '-in', `${name}.csr`, '-CA', `${issuer.name}.pem`, '-CAkey', `${issuer.name}.key`,
        '-CAcreateserial', '-not_before', validity[0], '-not_after', validity[1], '-out', `${name}.pem`];
    if (extensions.length > 0) {
        args.push('-extfile', writeExtensions(name, extensions), '-extensions', 'v3');
    }
    openssl(...args);
    const privateKey = crypto.createPrivateKey(fs.readFileSync(path.join(work, `${name}.key`)));
    return {
        name,
        der: der(name),
        publicJwk: JSON.stringify(crypto.createPublicKey(privateKey).export({ format: 'jwk' })),
        privateJwk: JSON.stringify(privateKey.export({ format: 'jwk' })),
    };
}

/** `openssl verify`'s verdict on `chain` (signer first), trusting only `anchors`. */
function opensslVerdict(chain, anchors, validationTime) {
    const toPem = (bytes) => `-----BEGIN CERTIFICATE-----\n${bytes.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
    fs.writeFileSync(path.join(work, 'verify-anchors.pem'), anchors.map((a) => toPem(a.der)).join(''));
    fs.writeFileSync(path.join(work, 'verify-leaf.pem'), toPem(chain[0]));
    const args = ['verify', '-attime', String(validationTime), '-CAfile', 'verify-anchors.pem'];
    if (chain.length > 1) {
        fs.writeFileSync(path.join(work, 'verify-untrusted.pem'), chain.slice(1).map(toPem).join(''));
        args.push('-untrusted', 'verify-untrusted.pem');
    }
    args.push('verify-leaf.pem');
    try {
        openssl(...args);
        return { accepted: true };
    } catch (error) {
        const output = `${error.stdout ?? ''}${error.stderr ?? ''}`;
        return { accepted: false, error: output.split('\n').find((line) => line.startsWith('error')) ?? output.trim() };
    }
}

function flipLastByte(bytes) {
    const copy = Buffer.from(bytes);
    copy[copy.length - 1] ^= 0x01;
    return copy;
}

const root = makeRoot('root');
const otherRoot = makeRoot('other-root');
const constrainedRoot = makeRoot('constrained-root', ['basicConstraints=critical,CA:TRUE,pathlen:0', 'keyUsage=critical,keyCertSign,cRLSign']);

const intermediate = issue('intermediate', root, { keyType: 'p384', extensions: CA_EXTENSIONS, validity: ['20190101000000Z', '20400101000000Z'] });
const expiredIntermediate = issue('expired-intermediate', root, { extensions: CA_EXTENSIONS, validity: ['20200101000000Z', '20210101000000Z'] });
const notCA = issue('not-a-ca', root, { extensions: ['basicConstraints=critical,CA:FALSE'] });
const noCertSign = issue('no-cert-sign', root, { extensions: ['basicConstraints=critical,CA:TRUE', 'keyUsage=critical,digitalSignature'] });
const underConstrained = issue('under-constrained', constrainedRoot, { extensions: CA_EXTENSIONS });

const ecLeaf = issue('ec-leaf', root);
const rsaLeaf = issue('rsa-leaf', intermediate, { keyType: 'rsa' });
const p521Leaf = issue('p521-leaf', intermediate, { keyType: 'p521' });
const edLeaf = issue('ed25519-leaf', intermediate, { keyType: 'ed25519' });
const signingLeaf = issue('signing-leaf', root, { extensions: ['keyUsage=critical,digitalSignature'] });
const expiredLeaf = issue('expired-leaf', root, { validity: ['20200101000000Z', '20210101000000Z'] });
const futureLeaf = issue('future-leaf', root, { validity: ['20350101000000Z', '20400101000000Z'] });
const otherLeaf = issue('other-leaf', otherRoot);
const leafOfNotCA = issue('leaf-of-not-a-ca', notCA);
const leafOfNoCertSign = issue('leaf-of-no-cert-sign', noCertSign);
const leafOfConstrained = issue('leaf-of-constrained', underConstrained);
const leafOfExpired = issue('leaf-of-expired-intermediate', expiredIntermediate);
const unknownCritical = issue('unknown-critical-leaf', root, { extensions: ['1.3.6.1.4.1.55555.1=critical,DER:05:00'] });
const encipherOnly = issue('encipherment-leaf', root, { extensions: ['keyUsage=critical,keyEncipherment'] });
// A key usage extension holding NULL where its BIT STRING belongs.
const malformedKeyUsage = issue('malformed-key-usage-leaf', root, { extensions: ['2.5.29.15=critical,DER:05:00'] });
const secp256k1Leaf = issue('secp256k1-leaf', root, { keyType: 'secp256k1' });

const cases = [];
function addCase(name, chain, anchors, { leaf = chain[0], validationTime = VALIDATION_TIME } = {}) {
    const ders = chain.map((certificate) => (Buffer.isBuffer(certificate) ? certificate : certificate.der));
    cases.push({
        name,
        anchors: anchors.map((anchor) => anchor.name),
        chain: ders.map((bytes) => bytes.toString('hex')),
        validationTime,
        publicJwk: leaf.publicJwk,
        privateJwk: leaf.privateJwk,
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
addCase('leaf signature altered', [flipLastByte(ecLeaf.der)], [root], { leaf: ecLeaf });
addCase('unknown critical extension', [unknownCritical], [root]);
addCase('leaf key usage without digitalSignature', [encipherOnly], [root]);
addCase('malformed key usage', [malformedKeyUsage], [root]);
addCase('secp256k1 leaf', [secp256k1Leaf], [root]);

assert(cases[0].openssl.accepted, 'the positive control verifies');
assert(cases.some((c) => !c.openssl.accepted), 'some chains are refused');

const fixture = {
    _generated: {
        notice: 'GENERATED FILE. Do not edit by hand; rerun interop/x509/generate-fixtures.mjs.',
        generator: 'interop/x509/generate-fixtures.mjs',
        description: "Certificate chains made by OpenSSL, with `openssl verify`'s verdict on each.",
        openssl: openssl('version').toString().trim(),
        node: process.version,
    },
    anchors: {
        [root.name]: root.der.toString('hex'),
        [otherRoot.name]: otherRoot.der.toString('hex'),
        [constrainedRoot.name]: constrainedRoot.der.toString('hex'),
    },
    cases,
};
fs.mkdirSync(fixturesDirectory, { recursive: true });
fs.writeFileSync(path.join(fixturesDirectory, 'chains.json'), JSON.stringify(fixture, null, 2) + '\n');
fs.rmSync(work, { recursive: true, force: true });
console.log('wrote chains.json');
