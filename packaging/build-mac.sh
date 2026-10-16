#!/usr/bin/env bash
# build-mac.sh — binario autosuficiente de dotrino-vault para macOS (universal: arm64 + x64).
#
# Misma estrategia que `build.sh` (Node SEA). Lo que cambia en macOS:
#
#  · Se corre EN un Mac (hacen falta `codesign` y `lipo`). En CI, el runner `macos-14`.
#  · El blob se genera con el Node oficial de la MISMA versión que se inyecta: el formato
#    del blob cambia entre versiones (ver build-win.sh).
#  · Cada arquitectura se inyecta por separado (postject no sabe parchear un binario
#    universal) y después se juntan con `lipo`.
#  · Inyectar invalida la firma de Node, así que se quita antes y se firma «ad hoc» después:
#    sin firma, un binario arm64 ni siquiera arranca. Ad hoc no es una firma de Apple: el
#    sistema avisa al abrirlo la primera vez (Gatekeeper). Firmar y notarizar pide una
#    cuenta de desarrollador de pago, y se dice en vez de esconderlo.
#
#   bash packaging/build-mac.sh   → dist/dotrino-vaultd-macos (universal)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
WORK="$ROOT/.build-mac"
VER="$(node -p "require('$ROOT/package.json').version")"
NODE_VER="${DOTRINO_NODE_VER:-v22.20.0}"
HOST_ARCH="$(uname -m)"; [ "$HOST_ARCH" = "x86_64" ] && HOST_ARCH=x64

echo "dotrino-vault · build v$VER para macOS universal (SEA sobre node $NODE_VER)"
rm -rf "$WORK"; mkdir -p "$WORK" "$DIST"

echo "  → bundling con esbuild…"
npx --yes esbuild "$ROOT/bin/sea-entry.js" \
  --bundle --platform=node --format=cjs --target=node20 \
  --define:__VAULT_VERSION__="\"$VER\"" \
  --outfile="$WORK/bundle.cjs" \
  --banner:js="globalThis.__DOTRINO_SEA__=true;"

cat > "$WORK/sea-config.json" <<JSON
{
  "main": "$WORK/bundle.cjs",
  "output": "$WORK/sea-prep.blob",
  "disableExperimentalSEAWarning": true,
  "useSnapshot": false,
  "useCodeCache": false
}
JSON

fetch_node () { # $1 = arm64 | x64
  local d="node-$NODE_VER-darwin-$1"
  if [ ! -x "$WORK/$d/bin/node" ]; then
    echo "  → bajando ${d}…" >&2
    curl -fsSL "https://nodejs.org/dist/$NODE_VER/$d.tar.gz" | tar -xz -C "$WORK"
  fi
  echo "$WORK/$d/bin/node"
}

echo "  → generando blob SEA con node ${NODE_VER}…"
"$(fetch_node "$HOST_ARCH")" --experimental-sea-config "$WORK/sea-config.json"

SLICES=()
for arch in arm64 x64; do
  src="$(fetch_node "$arch")"
  out="$WORK/dotrino-vaultd-$arch"
  cp "$src" "$out"
  codesign --remove-signature "$out"
  echo "  → inyectando blob ($arch)…"
  npx --yes postject "$out" NODE_SEA_BLOB "$WORK/sea-prep.blob" \
    --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2 \
    --macho-segment-name NODE_SEA
  SLICES+=("$out")
done

OUT="$DIST/dotrino-vaultd-macos"
lipo -create -output "$OUT" "${SLICES[@]}"
codesign --sign - --force "$OUT"
chmod 0755 "$OUT"
echo "$VER" > "$DIST/.version-macos"

echo
echo "OK: $OUT ($(du -h "$OUT" | cut -f1)) — $(lipo -archs "$OUT")"
