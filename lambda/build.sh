#!/usr/bin/env bash
# Arma el código de la Lambda y la plantilla que lo apunta (ver README.md).
#
#   lambda/build.sh [--demo] [<url del zip>]
#
# --demo añade el agente de Dotrino Terminal (`Mode: demo`, ver demo.mjs). No va en la release:
# solo lo usa la demo para quien revisa las apps, y se despliega con `deploy.sh --mode demo`.
#
# Deja en dist/:
#   dotrino-vault-lambda-<versión>.zip    el código
#   dotrino-vault-lambda-<versión>.yaml   la plantilla, con la URL y el hash del zip ya puestos
#
# Sin URL, la de la release de GitHub de esta versión: es lo que hace release.yml.
set -euo pipefail
DEMO=
if [ "${1:-}" = "--demo" ]; then DEMO=1; shift; fi
# La versión del agente de la demo: se sube a mano, como el pin de la imagen de Timone.
TERMINAL_AGENT=0.49.1
HERE=$(cd "$(dirname "$0")" && pwd)
REPO=$(cd "$HERE/.." && pwd)
V=$(node -p "require('$REPO/package.json').version")
NAME=dotrino-vault-lambda-$V
URL=${1:-https://github.com/imdotrino/dotrino-vault/releases/download/v$V/$NAME.zip}
BUILD="$HERE/build"

rm -rf "$BUILD"; mkdir -p "$BUILD/lib" "$BUILD/packaging" "$BUILD/lambda" "$REPO/dist"
cp "$REPO/package.json" "$REPO/package-lock.json" "$BUILD/"
# LOS AGENTES DE PROXY EN SU VERSIÓN COMMONJS, solo en la Lambda. `sigstore` (con el que la
# bóveda verifica lo que baja, `update.mjs`) carga `@npmcli/agent`, que hace require() de cuatro
# paquetes que en su última versión son solo ESM; el Node de Lambda no deja hacer require() de
# ESM (ERR_REQUIRE_ESM, también con nodejs24.x, visto en AWS el 2026-10-25). Las versiones de
# abajo tienen la misma interfaz y son CommonJS; probado con `--no-experimental-require-module`
# verificando el zip de una release real.
node -e '
const f = process.argv[1], p = JSON.parse(require("fs").readFileSync(f, "utf8"))
p.overrides = { ...(p.overrides || {}), "agent-base": "7.1.4", "http-proxy-agent": "7.0.2", "https-proxy-agent": "7.0.6", "socks-proxy-agent": "8.0.5" }
require("fs").writeFileSync(f, JSON.stringify(p, null, 2) + "\n")' "$BUILD/package.json"
cp -r "$REPO/bin" "$REPO/src" "$REPO/vendor" "$BUILD/"
cp -r "$REPO/lib/src" "$BUILD/lib/"
cp "$REPO/packaging/kms-aws.mjs" "$BUILD/packaging/"
cp "$HERE"/*.mjs "$BUILD/lambda/"
(cd "$BUILD" && npm install --omit=dev --ignore-scripts --no-audit --no-fund --loglevel=error)
if [ -n "$DEMO" ]; then
  cp "$HERE/demo-shell.sh" "$BUILD/lambda/" && chmod 755 "$BUILD/lambda/demo-shell.sh"
  (cd "$BUILD" && npm install --no-save --omit=dev --ignore-scripts --no-audit --no-fund --loglevel=error "@dotrino/terminal-agent@$TERMINAL_AGENT")
  NAME=$NAME-demo
fi
rm -f "$REPO/dist/$NAME.zip"
(cd "$BUILD" && find . -exec touch -h -d '2000-01-01T00:00:00Z' {} + && find . -type f | LC_ALL=C sort | zip -qX -@ "$REPO/dist/$NAME.zip")
SHA=$(sha256sum "$REPO/dist/$NAME.zip" | cut -d' ' -f1)
sed -e "s#__CODE_URL__#$URL#" -e "s#__CODE_SHA256__#$SHA#" -e "s#__VERSION__#$V#" "$HERE/template.yaml" > "$REPO/dist/$NAME.yaml"
echo "$REPO/dist/$NAME.zip  sha256 $SHA"
echo "$REPO/dist/$NAME.yaml"
