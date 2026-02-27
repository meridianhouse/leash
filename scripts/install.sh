#!/bin/bash
# Leash installer
# WARNING: Do not execute remote scripts directly (avoid curl|bash).
# Download this script, verify checksum, inspect it, then run it locally.
set -e

echo "🐕 Installing Leash..."
echo ""

PINNED_REF="055f4517c120b6d9039e597c7a2c907e8ed92dee"
PINNED_ARCHIVE_SHA256="b94445cbf6ce8864b6bf3869222f95ef6f432f6fbba4466f51a17b166250726f"
SOURCE_URL="https://codeload.github.com/meridianhouse/leash/tar.gz/${PINNED_REF}"

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo "Rust (cargo) is required. Install Rust from https://rustup.rs and re-run this installer."
    exit 1
fi

# Check build toolchain prerequisites
if ! command -v cc &> /dev/null && ! command -v gcc &> /dev/null && ! command -v clang &> /dev/null; then
    echo "A C compiler/linker is required (cc/gcc/clang)."
    echo "On Ubuntu/Debian: sudo apt-get install -y build-essential"
    exit 1
fi

if ! command -v pkg-config &> /dev/null; then
    echo "pkg-config is required."
    echo "On Ubuntu/Debian: sudo apt-get install -y pkg-config"
    exit 1
fi

if [[ ! -f /usr/include/openssl/ssl.h ]] && [[ ! -f /usr/local/include/openssl/ssl.h ]]; then
    echo "OpenSSL development headers are required (ssl.h not found)."
    echo "On Ubuntu/Debian: sudo apt-get install -y libssl-dev"
    exit 1
fi

# Check for Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "⚠️  Leash currently supports Linux only. macOS support coming in v0.2."
    exit 1
fi

# Download pinned source tarball and verify checksum
TMPDIR=$(mktemp -d)
ARCHIVE="$TMPDIR/leash.tar.gz"
echo "Downloading pinned source ($PINNED_REF)..."
curl -fsSL "$SOURCE_URL" -o "$ARCHIVE"

if command -v sha256sum &> /dev/null; then
    ACTUAL_SHA256=$(sha256sum "$ARCHIVE" | awk '{print $1}')
elif command -v shasum &> /dev/null; then
    ACTUAL_SHA256=$(shasum -a 256 "$ARCHIVE" | awk '{print $1}')
else
    echo "A SHA-256 tool is required (sha256sum or shasum)."
    exit 1
fi

if [[ "$ACTUAL_SHA256" != "$PINNED_ARCHIVE_SHA256" ]]; then
    echo "Checksum verification failed."
    echo "Expected: $PINNED_ARCHIVE_SHA256"
    echo "Actual:   $ACTUAL_SHA256"
    exit 1
fi

echo "Checksum verified."
mkdir -p "$TMPDIR/src"
tar -xzf "$ARCHIVE" -C "$TMPDIR/src" --strip-components=1
cd "$TMPDIR/src"

echo "Building from source..."
cargo build --release

# Install binary
INSTALL_DIR="${HOME}/.local/bin"
mkdir -p "$INSTALL_DIR"
cp target/release/leash "$INSTALL_DIR/leash"
strip "$INSTALL_DIR/leash"

# Cleanup
rm -rf "$TMPDIR"

# Check PATH
if [[ ":$PATH:" != *":$INSTALL_DIR:"* ]]; then
    echo ""
    echo "Add to your PATH:"
    echo "  export PATH=\"$INSTALL_DIR:\$PATH\""
    echo ""
fi

echo ""
echo "✅ Leash installed to $INSTALL_DIR/leash"
echo ""
echo "Get started:"
echo "  leash init     # Generate config"
echo "  leash watch    # Start monitoring"
echo ""
echo "🐕 Put your AI on a short leash."
