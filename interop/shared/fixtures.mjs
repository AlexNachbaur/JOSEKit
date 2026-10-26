// Shared by the fixture generators: how a fixture file is written, and the generators' self-checks.

import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import josePackage from 'jose/package.json' with { type: 'json' };

export const joseVersion = josePackage.version;

const repositoryDirectory = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');

/**
 * A function that writes fixtures into `Tests/<testTarget>/Fixtures`. `generatorURL` is the
 * generator's `import.meta.url`: each fixture names the script that wrote it, and the versions of
 * the tools behind it, so that it can be traced and regenerated. `metadata` adds to those.
 */
export function fixtureWriter(generatorURL, testTarget) {
    const generator = path.relative(repositoryDirectory, fileURLToPath(generatorURL));
    const directory = path.join(repositoryDirectory, 'Tests', testTarget, 'Fixtures');
    return function write(name, description, body, metadata = {}) {
        const fixture = {
            _generated: {
                notice: `GENERATED FILE. Do not edit by hand; rerun ${generator}.`,
                generator,
                description,
                jose: joseVersion,
                node: process.version,
                openssl: process.versions.openssl,
                ...metadata,
            },
            ...body,
        };
        fs.mkdirSync(directory, { recursive: true });
        fs.writeFileSync(path.join(directory, name), JSON.stringify(fixture, null, 2) + '\n');
        console.log(`wrote ${name}`);
    };
}

/** Stops the generator if something it is about to write down is not what it claims. */
export function assert(condition, message) {
    if (!condition) {
        throw new Error(`fixture generation self-check failed: ${message}`);
    }
}

/** A copy of `buffer` with its last bit inverted: the smallest change that should break a check. */
export function flipLastBit(buffer) {
    const copy = Buffer.from(buffer);
    copy[copy.length - 1] ^= 0x01;
    return copy;
}
