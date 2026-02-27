#!/usr/bin/env bash
set -euo pipefail

VERSION=${1:-}
if [[ -z "$VERSION" ]]; then
  echo "Usage: $0 <version>   e.g. v0.2.0"
  exit 1
fi

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT="$ROOT/dist/$VERSION"
mkdir -p "$OUT"

BIN="$ROOT/target/release/leash"
if [[ ! -f "$BIN" ]]; then
  echo "Missing $BIN (build first: cargo build --release)"
  exit 1
fi

cp "$BIN" "$OUT/leash-linux-x86_64"
sha256sum "$OUT/leash-linux-x86_64" > "$OUT/SHA256SUMS.txt"

cat <<EOF
Release artifacts ready:
  $OUT/leash-linux-x86_64
  $OUT/SHA256SUMS.txt
EOF
