// Shared by the closed-loop checks: the command line, and the tally of what was checked.
//
// A closed-loop script exports nothing; it calls `runClosedLoop` with two functions:
//
//     challenge(file)                      writes the challenge for the Swift side to answer
//     verify(challenge, response, checks)  judges the response, recording each check
//
// and is run as `node <script> challenge <challenge.json>` and
// `node <script> verify <challenge.json> <response.json>`.

import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';

/**
 * What a closed-loop check found: how many checks ran in each section, and which failed. The
 * methods are bound, so a script can take them out: `const { check, refuses } = checks`.
 */
export class Checks {
    #counts = {};
    #failures = [];

    /** Counts a check in `section`, and records it as failed unless `condition` holds. */
    check = (section, label, condition, detail) => {
        this.#counts[section] = (this.#counts[section] ?? 0) + 1;
        if (!condition) {
            this.#failures.push(`${section} ${label}: ${detail}`);
        }
    };

    /** Records a failure that is not one of a section's counted checks. */
    fail = (message) => {
        this.#failures.push(message);
    };

    /** How many checks have run in `section`. */
    count = (section) => this.#counts[section] ?? 0;

    /**
     * Checks that `run`, which asks the counterpart to accept something, throws. `outcome` says
     * what the counterpart did when it did not.
     */
    refuses = async (section, label, run, outcome = 'jose accepted it') => {
        try {
            await run();
            this.check(section, label, false, outcome);
        } catch {
            this.check(section, label, true, '');
        }
    };

    /** Prints the tally, and exits non-zero if anything failed. */
    report(name) {
        for (const [section, count] of Object.entries(this.#counts)) {
            console.log(`${section}: ${count} checked`);
        }
        if (this.#failures.length > 0) {
            console.error(`\n${this.#failures.length} FAILURES`);
            for (const failure of this.#failures.slice(0, 20)) {
                console.error(`  ${failure}`);
            }
            process.exit(1);
        }
        console.log(`${name}: all checks passed`);
    }
}

/** Whether two JSON values are equal, member for member. */
export function sameJSON(actual, expected) {
    try {
        assert.deepEqual(actual, expected);
        return true;
    } catch {
        return false;
    }
}

/** Runs a closed-loop script's `challenge` or `verify` step, as its command line asks. */
export async function runClosedLoop({ challenge, verify, name = 'closed loop' }) {
    const [command, ...files] = process.argv.slice(2);
    if (command === 'challenge' && files.length === 1) {
        await challenge(files[0]);
    } else if (command === 'verify' && files.length === 2) {
        const [challengeJSON, responseJSON] = files.map((file) => JSON.parse(fs.readFileSync(file, 'utf8')));
        const checks = new Checks();
        await verify(challengeJSON, responseJSON, checks);
        checks.report(name);
    } else {
        const script = path.basename(process.argv[1]);
        console.error(`usage: ${script} challenge <challenge.json> | verify <challenge.json> <response.json>`);
        process.exit(2);
    }
}
