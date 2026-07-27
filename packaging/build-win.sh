#!/usr/bin/env bash
# build-win.sh — binario autosuficiente para WINDOWS x64, construido desde Linux.
#
# Misma estrategia que `build.sh` (Node SEA), con una diferencia: en vez de copiar el
# `node` de esta máquina, se **descarga el node.exe oficial de Windows** y se le inyecta
# el mismo blob. `postject` parchea el recurso PE igual que el ELF, así que el cruce
# funciona sin toolchain de Windows.
#
#   bash packaging/build-win.sh          → dist/dotrino-vaultd.exe + .zip
#
# ⚠️ DOS COSAS QUE HAY QUE DECIR:
#
#  1. **Se construye aquí pero no se puede PROBAR aquí.** Que el .exe se genere no
#     demuestra que arranque en Windows. Hasta correrlo en un Windows de verdad, este
#     artefacto es un candidato, no una release. La vía sostenida en Windows —la que sí
#     está probada— es `npx -y @dotrino/vaultd` o Docker.
#  2. **Rompe la firma de Microsoft.** El node.exe oficial viene firmado; inyectarle el
#     blob invalida esa firma, así que Windows mostrará el aviso de SmartScreen
#     («editor desconocido»). Firmarlo cuesta un certificado EV: por eso la landing lo
#     dice en voz alta en vez de que el usuario se lo encuentre.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
WORK="$ROOT/.build-win"
VER="$(node -p "require('$ROOT/package.json').version")"
# La misma línea de Node que usa el instalador universal del ecosistema (install.ps1).
NODE_VER="${DOTRINO_NODE_VER:-v22.20.0}"

echo "dotrino-vault · build v$VER para Windows x64 (SEA sobre node $NODE_VER)"
rm -rf "$WORK"; mkdir -p "$WORK" "$DIST"

# --- 1. bundle (idéntico al de Linux: mismo código, mismo entry) --------------
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
# `useCodeCache` NO se puede usar cruzando de plataforma: la caché de código es del
# binario que la generó. Con `false` arranca un pelo más lento y es portable.
echo "  → generando blob SEA…"
node --experimental-sea-config "$WORK/sea-config.json"

# --- 2. node.exe oficial de Windows ------------------------------------------
ZIPNAME="node-$NODE_VER-win-x64"
if [ ! -f "$WORK/$ZIPNAME/node.exe" ]; then
  echo "  → bajando $ZIPNAME…"
  curl -fsSL -o "$WORK/node.zip" "https://nodejs.org/dist/$NODE_VER/$ZIPNAME.zip"
  unzip -q "$WORK/node.zip" -d "$WORK"
fi

OUT="$DIST/dotrino-vaultd.exe"
cp "$WORK/$ZIPNAME/node.exe" "$OUT"
echo "  → inyectando blob en el .exe…"
npx --yes postject "$OUT" NODE_SEA_BLOB "$WORK/sea-prep.blob" \
  --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2

# --- 3. el CLI es el MISMO binario (multicall por argv) -----------------------
cat > "$DIST/dotrino-vault.cmd" <<'WRAP'
@echo off
rem Wrapper del CLI de control: delega en el binario autosuficiente.
"%~dp0dotrino-vaultd.exe" --ctl %*
WRAP

# --- 4. zip distribuible ------------------------------------------------------
STAGE="$WORK/dotrino-vault-$VER-win-x64"
mkdir -p "$STAGE"
cp "$OUT" "$DIST/dotrino-vault.cmd" "$STAGE/"
cp "$ROOT/README.md" "$STAGE/" 2>/dev/null || true
ZIPOUT="$DIST/dotrino-vault-$VER-win-x64.zip"
(cd "$WORK" && zip -qr "$ZIPOUT" "dotrino-vault-$VER-win-x64")

echo
echo "OK (SIN PROBAR EN WINDOWS — ver la advertencia de arriba):"
echo "  binario  $OUT   ($(du -h "$OUT" | cut -f1))"
echo "  zip      $ZIPOUT ($(du -h "$ZIPOUT" | cut -f1))"
