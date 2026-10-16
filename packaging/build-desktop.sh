#!/usr/bin/env bash
# build-desktop.sh — la ventana de control (desktop/, Rust + iced) para Linux x64.
#
# La ventana no sabe nada de la bóveda: lanza `dotrino-vaultd --gui-bridge` y pinta lo que le
# manda (ver desktop/src/main.rs y src/tui/gui.js). Por eso se compila aparte y viaja en los
# mismos paquetes que el daemon (.deb, .rpm y el tarball), al lado de él.
#
#   bash packaging/build-desktop.sh   → dist/dotrino-vault-desktop
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DIST="$ROOT/dist"
VER="$(node -p "require('$ROOT/package.json').version")"
CVER="$(sed -n 's/^version = "\(.*\)"/\1/p' desktop/Cargo.toml | head -1)"
# Una sola versión para el producto: la ventana sale con la bóveda con la que se publica.
[ "$CVER" = "$VER" ] || { echo "ERROR: desktop/Cargo.toml dice $CVER y package.json $VER" >&2; exit 1; }
command -v cargo >/dev/null || { echo "ERROR: cargo not found (https://rustup.rs)" >&2; exit 1; }

mkdir -p "$DIST"
(cd desktop && cargo build --release --locked)
install -m0755 desktop/target/release/dotrino-vault-desktop "$DIST/dotrino-vault-desktop"
echo "$VER" > "$DIST/.desktop-version"
echo "OK -> $DIST/dotrino-vault-desktop ($(du -h "$DIST/dotrino-vault-desktop" | cut -f1))"
