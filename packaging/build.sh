#!/usr/bin/env bash
# build.sh — produce el binario AUTOSUFICIENTE de dotrino-vault para Linux x64.
#
# Estrategia v1: Node Single Executable Application (SEA) — Node embebido en un
# único binario, sin que el usuario instale Node. Sin firma de código.
#
# Empaqueta el daemon + el CLI de control + todos los node_modules en un bundle
# y lo inyecta en una copia del binario `node`. Salida en  dist/.
#
# Requisitos en la máquina de BUILD (no en la del usuario): node >=20 y npm.
#   (esbuild se instala on-the-fly con npx si no está.)
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
DIST="$ROOT/dist"
WORK="$ROOT/.build"
NODE_BIN="$(command -v node)"
VER="$(node -p "require('$ROOT/package.json').version")"

echo "dotrino-vault · build v$VER (SEA, Node $(node --version))"
rm -rf "$WORK" "$DIST"
mkdir -p "$WORK" "$DIST"

# --- 1. bundle de TODO a un solo CJS (resuelve ESM + node_modules) ------------
# El SEA arranca un CommonJS; usamos esbuild para colapsar el grafo ESM (incluido
# @dotrino/identity, @dotrino/proxy-client y ws) en un único archivo. `ws` es JS
# puro (sin addon nativo), así que entra sin problemas en el SEA.
echo "  → bundling con esbuild…"
npx --yes esbuild "$ROOT/bin/sea-entry.js" \
  --bundle --platform=node --format=cjs --target=node20 \
  --outfile="$WORK/bundle.cjs" \
  --banner:js="globalThis.__DOTRINO_SEA__=true;"

# --- 2. config SEA ------------------------------------------------------------
cat > "$WORK/sea-config.json" <<JSON
{
  "main": "$WORK/bundle.cjs",
  "output": "$WORK/sea-prep.blob",
  "disableExperimentalSEAWarning": true,
  "useSnapshot": false,
  "useCodeCache": true
}
JSON

echo "  → generando blob SEA…"
node --experimental-sea-config "$WORK/sea-config.json"

# --- 3. copiar node y inyectar el blob ---------------------------------------
OUT="$DIST/dotrino-vaultd"
cp "$NODE_BIN" "$OUT"
# Quitar firma no aplica en Linux (ELF sin firmar). Inyectamos el fuse.
echo "  → inyectando blob en el binario…"
npx --yes postject "$OUT" NODE_SEA_BLOB "$WORK/sea-prep.blob" \
  --sentinel-fuse NODE_SEA_FUSE_fce680ab2cc467b6e072b8b5df1996b2
chmod 0755 "$OUT"

# --- 4. el CLI de control es el MISMO binario (multi-call por argv[1]) ---------
# Para no duplicar peso, `dotrino-vault` es un wrapper que invoca el binario con
# un primer arg de subcomando. (El entry detecta el modo por argv.)
cat > "$DIST/dotrino-vault" <<'WRAP'
#!/usr/bin/env sh
# Wrapper del CLI de control: delega en el binario autosuficiente.
exec "$(dirname "$0")/dotrino-vaultd" --ctl "$@"
WRAP
chmod 0755 "$DIST/dotrino-vault"

# --- 5. armar el tarball distribuible ----------------------------------------
STAGE="$WORK/dotrino-vault-$VER-linux-x64"
mkdir -p "$STAGE"
cp "$DIST/dotrino-vaultd" "$DIST/dotrino-vault" "$STAGE/"
cp "$ROOT/packaging/install.sh" "$ROOT/packaging/uninstall.sh" "$STAGE/"
cp "$ROOT/packaging/dotrino-vault.service" "$STAGE/"
cp "$ROOT/README.md" "$STAGE/" 2>/dev/null || true
chmod +x "$STAGE/install.sh" "$STAGE/uninstall.sh"
TARBALL="$DIST/dotrino-vault-$VER-linux-x64.tar.gz"
tar -C "$WORK" -czf "$TARBALL" "dotrino-vault-$VER-linux-x64"

echo
echo "OK:"
echo "  binario  $DIST/dotrino-vaultd   ($(du -h "$DIST/dotrino-vaultd" | cut -f1))"
echo "  tarball  $TARBALL               ($(du -h "$TARBALL" | cut -f1))"
echo
echo "El usuario hace:  tar xzf $(basename "$TARBALL") && cd dotrino-vault-$VER-linux-x64 && sh install.sh"
