// Certificates made with the OpenSSL command line, shared by the certificate fixture generators.

import { execFileSync } from 'node:child_process';
import crypto from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';

/** `openssl` arguments that generate a key of each type. */
export const KEY_TYPES = {
    p256: ['ecparam', '-name', 'prime256v1', '-genkey', '-noout'],
    p384: ['ecparam', '-name', 'secp384r1', '-genkey', '-noout'],
    p521: ['ecparam', '-name', 'secp521r1', '-genkey', '-noout'],
    secp256k1: ['ecparam', '-name', 'secp256k1', '-genkey', '-noout'],
    rsa: ['genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048'],
    ed25519: ['genpkey', '-algorithm', 'ed25519'],
};

export const CA_EXTENSIONS = ['basicConstraints=critical,CA:TRUE', 'keyUsage=critical,keyCertSign,cRLSign'];

/** Fixed, so that verdicts on a fixture do not change as it ages. */
const DEFAULT_VALIDITY = ['20250101000000Z', '20350101000000Z'];

/** A DER certificate in PEM form. */
export function toPEM(der) {
    const lines = der.toString('base64').match(/.{1,64}/g).join('\n');
    return `-----BEGIN CERTIFICATE-----\n${lines}\n-----END CERTIFICATE-----\n`;
}

/** A scratch directory in which OpenSSL makes keys and certificates. Call `remove()` when done. */
export class PKI {
    #work = fs.mkdtempSync(path.join(os.tmpdir(), 'jose-pki-'));

    /** Runs `openssl` in the scratch directory and returns its standard output. */
    openssl(...args) {
        return execFileSync('openssl', args, { cwd: this.#work, stdio: ['ignore', 'pipe', 'pipe'] });
    }

    /** The OpenSSL command line's version, which may differ from the library inside Node. */
    get version() {
        return this.openssl('version').toString().trim();
    }

    /** Writes `contents` to `name` in the scratch directory, for an `openssl` argument. */
    writeFile(name, contents) {
        fs.writeFileSync(path.join(this.#work, name), contents);
    }

    /**
     * A self-signed P-256 CA, valid from 2019 to 2040, so that a certificate whose validity lies in
     * the past can still chain to it when a validator's clock is set back.
     */
    root(name, extensions = CA_EXTENSIONS) {
        this.openssl(...KEY_TYPES.p256, '-out', `${name}.key`);
        this.openssl('req', '-x509', '-new', '-key', `${name}.key`, '-subj', `/CN=${name}`, '-out', `${name}.pem`,
            '-not_before', '20190101000000Z', '-not_after', '20400101000000Z',
            ...extensions.flatMap((extension) => ['-addext', extension]));
        return { name, der: this.#der(name) };
    }

    /** A certificate for a new key of `keyType`, issued by `issuer`, with the key's private half. */
    issue(name, issuer, { keyType = 'p256', extensions = [], validity = DEFAULT_VALIDITY } = {}) {
        this.openssl(...KEY_TYPES[keyType], '-out', `${name}.key`);
        this.openssl('req', '-new', '-key', `${name}.key`, '-subj', `/CN=${name}`, '-out', `${name}.csr`);
        const args = ['x509', '-req', '-in', `${name}.csr`, '-CA', `${issuer.name}.pem`, '-CAkey', `${issuer.name}.key`,
            '-CAcreateserial', '-not_before', validity[0], '-not_after', validity[1], '-out', `${name}.pem`];
        if (extensions.length > 0) {
            this.writeFile(`${name}.ext`, `[v3]\n${extensions.join('\n')}\n`);
            args.push('-extfile', `${name}.ext`, '-extensions', 'v3');
        }
        this.openssl(...args);
        const privateKey = crypto.createPrivateKey(fs.readFileSync(path.join(this.#work, `${name}.key`)));
        return { name, der: this.#der(name), privateKey };
    }

    remove() {
        fs.rmSync(this.#work, { recursive: true, force: true });
    }

    #der(name) {
        return this.openssl('x509', '-in', `${name}.pem`, '-outform', 'DER');
    }
}
