#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v icp >/dev/null 2>&1; then
  echo "icp not found; run this script inside the project's nix-shell" >&2
  exit 1
fi
if ! command -v node >/dev/null 2>&1; then
  echo "node not found; run this script inside the project's nix-shell" >&2
  exit 1
fi

cleanup() {
  icp network stop test >/dev/null 2>&1 || true
}
trap cleanup EXIT

icp network stop test >/dev/null 2>&1 || true
icp network start test -d
icp deploy -e test -y

export CANISTER_ID="$(icp canister status key_exchange -e test -i)"
export IC_ROOT_KEY="$(icp network status -e test --json | python3 -c 'import sys,json; print(json.load(sys.stdin)["root_key"])')"
export IC_HOST="http://localhost:18080"

cd frontend
node test/e2e.mjs
