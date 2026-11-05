#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

if ! command -v vessel >/dev/null 2>&1; then
  echo "vessel not found; run this script inside the project's nix-shell" >&2
  exit 1
fi

if ! command -v wasmtime >/dev/null 2>&1; then
  echo "wasmtime not found; run this script inside the project's nix-shell" >&2
  exit 1
fi

vessel install

MOC="$(vessel bin)/moc"
SOURCES="$(vessel sources)"

mkdir -p .test
$MOC -wasi-system-api $SOURCES test/Unit.mo -o .test/unit.wasm
wasmtime .test/unit.wasm
