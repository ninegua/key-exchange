#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v icp >/dev/null 2>&1; then
  echo "icp not found; run this script inside the project's nix-shell" >&2
  exit 1
fi

cleanup() {
  icp network stop test >/dev/null 2>&1 || true
}
trap cleanup EXIT

icp network stop test >/dev/null 2>&1 || true
icp network start test -d
icp deploy -e test -y

OUT="$(icp canister call -e test key_exchange get_verification_key '()')"
echo "$OUT"
if ! grep -q 'blob' <<<"$OUT"; then
  echo "integration smoke test failed: expected a VetKeys verification key blob" >&2
  exit 1
fi

echo "LOCAL INTEGRATION SMOKE TEST PASSED"
