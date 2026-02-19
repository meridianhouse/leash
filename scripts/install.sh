#!/bin/bash
# Leash installer
# Usage: curl -sSL https://leash.meridianhouse.tech/install.sh | bash
set -e

echo "🐕 Installing Leash..."
echo ""

# Check for Rust
if ! command -v cargo &> /dev/null; then
    echo "Rust not found. Installing via rustup..."
    curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
    source "$HOME/.cargo/env"
fi

# Check for Linux
if [[ "$(uname)" != "Linux" ]]; then
    echo "⚠️  Leash currently supports Linux only. macOS support coming in v0.2."
    exit 1
fi

# Clone and build
TMPDIR=$(mktemp -d)
echo "Building from source..."
git clone --depth 1 https://github.com/meridianhouse/leash.git "$TMPDIR/leash"
cd "$TMPDIR/leash"
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
