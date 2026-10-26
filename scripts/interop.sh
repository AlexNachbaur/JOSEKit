#!/usr/bin/env bash
# Closed-loop interoperability checks against the Node counterpart (panva/jose, and OpenSSL for
# JOSECore). For each check, Node sets a challenge, the module's interop executable answers it,
# and Node judges the answers.
#
# With no arguments every module is checked. Name modules to check only those:
#     ./scripts/interop.sh jws jwe
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
work="$root/interop/.closed-loop"
mkdir -p "$work"

(cd "$root/interop" && npm ci --silent)

# One check: the Node script under interop/, the executable that answers it, and a name for its
# challenge and response files.
check() {
    local script="$1" executable="$2" name="$3"
    node "$root/interop/$script" challenge "$work/$name-challenge.json"
    swift run --package-path "$root" "$executable" < "$work/$name-challenge.json" > "$work/$name-response.json"
    node "$root/interop/$script" verify "$work/$name-challenge.json" "$work/$name-response.json"
}

modules=("$@")
if [ ${#modules[@]} -eq 0 ]; then
    modules=(core jwk jws jwe jwt secp256k1)
fi

for module in "${modules[@]}"; do
    echo "== $module"
    case "$module" in
    core) check core/closed-loop.mjs jose-core-interop core ;;
    jwk) check jwk/closed-loop.mjs jose-jwk-interop jwk ;;
    jws) check jws/closed-loop.mjs jose-jws-interop jws ;;
    jwe) check jwe/closed-loop.mjs jose-jwe-interop jwe ;;
    jwt)
        check jwt/closed-loop.mjs jose-jwt-interop jwt
        check jwt/closed-loop-encrypted.mjs jose-jwt-encrypted-interop jwt-encrypted
        ;;
    secp256k1) check secp256k1/closed-loop.mjs jose-secp256k1-interop secp256k1 ;;
    *)
        echo "unknown module '$module'; expected core, jwk, jws, jwe, jwt or secp256k1" >&2
        exit 2
        ;;
    esac
done
