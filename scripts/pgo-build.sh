#!/usr/bin/env bash
set -euo pipefail

# Profile-guided build pipeline:
# 1) instrumented build, 2) train with tests/workload, 3) optimized build using profile.

PGO_DIR="${PGO_DIR:-target/pgo-data}"
mkdir -p "$PGO_DIR"

if ! command -v llvm-profdata >/dev/null 2>&1; then
  echo "error: llvm-profdata is required for PGO (install llvm tools)" >&2
  exit 1
fi

echo "[1/3] Building instrumented binaries"
RUSTFLAGS="-Cprofile-generate=$PGO_DIR" cargo build --release

echo "[2/3] Training profile with test workload"
RUSTFLAGS="-Cprofile-generate=$PGO_DIR" cargo test --release || true

echo "[3/3] Merging profile data and building optimized binary"
llvm-profdata merge -o "$PGO_DIR/merged.profdata" "$PGO_DIR"/*.profraw
RUSTFLAGS="-Cprofile-use=$PGO_DIR/merged.profdata -Cllvm-args=-pgo-warn-missing-function" \
  cargo build --release

echo "PGO build complete: target/release/leash"
