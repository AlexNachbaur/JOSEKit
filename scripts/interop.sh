#!/usr/bin/env bash
# Closed-loop interoperability check against the Node counterpart (panva/jose and OpenSSL).
# Node sets a challenge, the Swift package answers it, Node judges the answers.
set -euo pipefail
# Use the sibling checkouts of the other JOSE packages rather than tagged releases.
export JOSE_LOCAL_PACKAGES=1

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$root/interop/.closed-loop"
mkdir -p "$work"

(cd "$root/interop" && npm ci --silent)
node "$root/interop/closed-loop.mjs" challenge "$work/challenge.json"
swift run --package-path "$root" jose-jwe-interop < "$work/challenge.json" > "$work/response.json"
node "$root/interop/closed-loop.mjs" verify "$work/challenge.json" "$work/response.json"
