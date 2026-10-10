#!/usr/bin/env bash
# Closed-loop interoperability checks against the Node counterpart (panva/jose): one for signed
# JWTs and one for encrypted and nested JWTs. Node sets a challenge, the Swift package answers
# it, Node judges the answers.
set -euo pipefail
# Use the sibling checkouts of the other JOSE packages rather than tagged releases.
export JOSE_LOCAL_PACKAGES=1

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$root/interop/.closed-loop"
mkdir -p "$work"

(cd "$root/interop" && npm ci --silent)

node "$root/interop/closed-loop.mjs" challenge "$work/challenge.json"
swift run --package-path "$root" jose-jwt-interop < "$work/challenge.json" > "$work/response.json"
node "$root/interop/closed-loop.mjs" verify "$work/challenge.json" "$work/response.json"

node "$root/interop/closed-loop-encrypted.mjs" challenge "$work/challenge-encrypted.json"
swift run --package-path "$root" jose-jwt-encrypted-interop \
    < "$work/challenge-encrypted.json" > "$work/response-encrypted.json"
node "$root/interop/closed-loop-encrypted.mjs" verify "$work/challenge-encrypted.json" "$work/response-encrypted.json"
