// Generates the certificate fixture in Tests/JOSEJWSTests/Fixtures/certificates.json with
// OpenSSL, for the x5c key-resolution tests.
//
//     cd interop && node generate-certificates.mjs
//
// A private CA signs two leaf certificates (one P-256, one RSA); a second CA exists so that a
// chain ending at the wrong anchor can be checked; one leaf is already expired. Keys and
// certificates are random on every run.

import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { exportJWK } from 'jose';

const fixturesDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../Tests/JOSEJWSTests/Fixtures');
const work = fs.mkdtempSync(path.join(os.tmpdir(), 'jose-certs-'));

function openssl(...args) {
    return execFileSync('openssl', args, { cwd: work, stdio: ['ignore', 'pipe', 'pipe'] });
}

function makeCA(name) {
    openssl('ecparam', '-name', 'prime256v1', '-genkey', '-noout', '-out', `${name}.key`);
    // Valid from 2019, so that a leaf whose validity lies in the past can still chain to it when
    // the validator's clock is set back.
    openssl('req', '-x509', '-new', '-key', `${name}.key`, '-subj', `/CN=${name}`, '-out', `${name}.pem`,
        '-not_before', '20190101000000Z', '-not_after', '20400101000000Z',
        '-addext', 'basicConstraints=critical,CA:TRUE', '-addext', 'keyUsage=critical,keyCertSign');
    return pemToDer(`${name}.pem`);
}

function makeLeaf(name, ca, keyArgs, validity = ['-days', '365']) {
    openssl(...keyArgs, '-out', `${name}.key`);
    openssl('req', '-new', '-key', `${name}.key`, '-subj', `/CN=${name}`, '-out', `${name}.csr`);
    openssl('x509', '-req', '-in', `${name}.csr`, '-CA', `${ca}.pem`, '-CAkey', `${ca}.key`, '-CAcreateserial', ...validity,
        '-out', `${name}.pem`, '-copy_extensions', 'none');
    return { der: pemToDer(`${name}.pem`), key: fs.readFileSync(path.join(work, `${name}.key`), 'utf8') };
}

function pemToDer(file) {
    return openssl('x509', '-in', file, '-outform', 'DER').toString('hex');
}

const root = makeCA('root');
const otherRoot = makeCA('other-root');
const ec = makeLeaf('ec-leaf', 'root', ['ecparam', '-name', 'prime256v1', '-genkey', '-noout']);
const rsa = makeLeaf('rsa-leaf', 'root', ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048']);
const expired = makeLeaf('expired-leaf', 'root', ['ecparam', '-name', 'prime256v1', '-genkey', '-noout'],
    ['-not_before', '20200101000000Z', '-not_after', '20210101000000Z']);
const underOther = makeLeaf('other-leaf', 'other-root', ['ecparam', '-name', 'prime256v1', '-genkey', '-noout']);

async function entry(leaf) {
    const privateKey = crypto.createPrivateKey(leaf.key);
    const publicKey = crypto.createPublicKey(privateKey);
    return {
        der: leaf.der,
        privateJwk: JSON.stringify(await exportJWK(privateKey)),
        publicJwk: JSON.stringify(await exportJWK(publicKey)),
        sha1: crypto.createHash('sha1').update(Buffer.from(leaf.der, 'hex')).digest('base64url'),
        sha256: crypto.createHash('sha256').update(Buffer.from(leaf.der, 'hex')).digest('base64url'),
    };
}

const fixture = {
    _generated: {
        notice: 'GENERATED FILE. Do not edit by hand; rerun interop/jws/generate-certificates.mjs.',
        generator: 'interop/jws/generate-certificates.mjs',
        description: 'A private CA, leaf certificates under it (P-256, RSA, one expired) and a leaf under another CA.',
        openssl: openssl('version').toString().trim(),
        node: process.version,
    },
    root,
    otherRoot,
    ecLeaf: await entry(ec),
    rsaLeaf: await entry(rsa),
    expiredLeaf: await entry(expired),
    leafUnderOtherRoot: await entry(underOther),
};
fs.writeFileSync(path.join(fixturesDirectory, 'certificates.json'), JSON.stringify(fixture, null, 2) + '\n');
fs.rmSync(work, { recursive: true, force: true });
console.log('wrote certificates.json');
