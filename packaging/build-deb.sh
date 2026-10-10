#!/usr/bin/env bash
# build-deb.sh — empaqueta dotrino-vault como paquete Debian (.deb) para amd64.
#
# El vault es POR-USUARIO (datos en tu $HOME, servicio `systemd --user`), pero un
# .deb instala a nivel sistema. La solución: el paquete trae el binario y un lanzador
# que lo copia a la carpeta de cada usuario (así se actualiza solo, sin sudo),
# instalar la UNIDAD DE USUARIO en /usr/lib/systemd/user/ y habilitarla
# para todos los usuarios (`systemctl --global enable`) en su próximo login. Cada
# usuario tiene su propia bóveda en ~/.local/share/dotrino/vault.
#
# Requiere: dpkg-deb. Usa el binario de packaging/build.sh (lo construye si falta).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DIST="$ROOT/dist"
VER="$(node -p "require('$ROOT/package.json').version")"

# 1. binario autosuficiente (Node embebido) — lo produce build.sh
#
# Y se reconstruye si el que hay en dist/ NO es de esta versión. Antes bastaba con que
# el archivo EXISTIERA: se empaquetó un .deb con el número nuevo y el binario viejo
# dentro, se instaló, y `status` seguía enseñando la versión anterior — un paquete que
# dice una cosa y hace otra, que es la peor forma de fallar (parece desplegado).
BUILT="$(cat "$DIST/.built-version" 2>/dev/null || echo '')"
if [ ! -f "$DIST/dotrino-vaultd" ] || [ "$BUILT" != "$VER" ]; then
  echo "==> el binario de dist/ es «${BUILT:-ninguno}» y toca «$VER»: reconstruyéndolo (build.sh)…"
  bash "$ROOT/packaging/build.sh"
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="dotrino-vault_${VER}_amd64"

# 2. layout del paquete
# El binario va en /usr/lib/dotrino-vault; en /usr/bin queda el LANZADOR, que lo copia a la
# carpeta del usuario y lo corre desde ahí: es la instalación de usuario, la única que se
# actualiza sola (pkg-launcher.sh).
install -D -m0755 "$DIST/dotrino-vaultd" "$STAGE/usr/lib/dotrino-vault/dotrino-vaultd"
install -D -m0755 "$DIST/dotrino-vault"  "$STAGE/usr/lib/dotrino-vault/dotrino-vault"
printf '%s\n' "$VER" > "$STAGE/usr/lib/dotrino-vault/VERSION"
chmod 0644 "$STAGE/usr/lib/dotrino-vault/VERSION"
install -D -m0755 "$ROOT/packaging/pkg-launcher.sh" "$STAGE/usr/bin/dotrino-vaultd"
install -D -m0755 "$ROOT/packaging/pkg-launcher.sh" "$STAGE/usr/bin/dotrino-vault"
install -D -m0644 "$ROOT/README.md"      "$STAGE/usr/share/doc/dotrino-vault/README.md"

# 3. unidad systemd --user (apunta al binario en /usr/bin). Es la misma del .rpm: vive en
# un archivo para que los dos paquetes no puedan decir cosas distintas.
install -D -m0644 "$ROOT/packaging/dotrino-vault.system.service" "$STAGE/usr/lib/systemd/user/dotrino-vault.service"
install -D -m0644 "$ROOT/packaging/dotrino-vault-dir.service" "$STAGE/usr/lib/systemd/user/dotrino-vault-dir.service"

# 4. metadatos de control
INSTALLED_KB="$(du -sk "$STAGE" | cut -f1)"
mkdir -p "$STAGE/DEBIAN"
cat > "$STAGE/DEBIAN/control" <<CONTROL
Package: dotrino-vault
Version: $VER
Architecture: amd64
Maintainer: Dotrino <hola@dotrino.com>
Section: utils
Priority: optional
Depends: systemd, libatomic1
Suggests: fido2-tools, yubikey-personalization
Homepage: https://vault.dotrino.com
Installed-Size: $INSTALLED_KB
Description: Your personal vault: all your information in one safe place
 Keep all your information -files, contacts, passwords and whatever your apps
 use- in a vault inside your own computer, not in a company's cloud. Private,
 secure and yours. No ads, no tracking. Free software (MIT).
 .
 The binary bundles everything (nothing else to install). It runs as a service
 of your session and your data lives only in your account.
CONTROL

# 5. post-install: habilitar la unidad de usuario para todos (arranca en el login)
cat > "$STAGE/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
systemctl daemon-reload 2>/dev/null || true
systemctl --global enable dotrino-vault.service >/dev/null 2>&1 || true
cat <<'MSG'

Dotrino Vault installed.
  - It starts on its own at your next login.
  - To start it now:          systemctl --user start dotrino-vault
  - If you are UPGRADING, the old service is still running: restart it with
      systemctl --user restart dotrino-vault
  - Check status:             dotrino-vault status
  - Connect a device:         dotrino-vault pair
Your data lives in ~/.local/share/dotrino/vault (only you can read it).

MSG
exit 0
POSTINST
chmod 0755 "$STAGE/DEBIAN/postinst"

# 6. post-remove: deshabilitar la unidad
cat > "$STAGE/DEBIAN/postrm" <<'POSTRM'
#!/bin/sh
set -e
if [ "$1" = "remove" ] || [ "$1" = "purge" ]; then
  systemctl --global disable dotrino-vault.service >/dev/null 2>&1 || true
fi
exit 0
POSTRM
chmod 0755 "$STAGE/DEBIAN/postrm"

# 7. construir
OUT="$DIST/$PKG.deb"
dpkg-deb --build --root-owner-group "$STAGE" "$OUT" >/dev/null

echo "OK -> $OUT  ($(du -h "$OUT" | cut -f1))"
