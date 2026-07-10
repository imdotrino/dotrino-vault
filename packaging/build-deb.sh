#!/usr/bin/env bash
# build-deb.sh — empaqueta dotrino-vault como paquete Debian (.deb) para amd64.
#
# El vault es POR-USUARIO (datos en tu $HOME, servicio `systemd --user`), pero un
# .deb instala a nivel sistema. La solución estándar: dejar los binarios en
# /usr/bin, instalar la UNIDAD DE USUARIO en /usr/lib/systemd/user/ y habilitarla
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
if [ ! -f "$DIST/dotrino-vaultd" ]; then
  echo "==> binario no encontrado, construyéndolo (build.sh)…"
  bash "$ROOT/packaging/build.sh"
fi

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
PKG="dotrino-vault_${VER}_amd64"

# 2. layout del paquete
install -D -m0755 "$DIST/dotrino-vaultd" "$STAGE/usr/bin/dotrino-vaultd"
install -D -m0755 "$DIST/dotrino-vault"  "$STAGE/usr/bin/dotrino-vault"
install -D -m0644 "$ROOT/README.md"      "$STAGE/usr/share/doc/dotrino-vault/README.md"

# 3. unidad systemd --user (apunta al binario en /usr/bin)
mkdir -p "$STAGE/usr/lib/systemd/user"
cat > "$STAGE/usr/lib/systemd/user/dotrino-vault.service" <<'UNIT'
[Unit]
Description=Dotrino Vault (tu bóveda personal)
Documentation=https://vault.dotrino.com
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=60
StartLimitBurst=10

[Service]
Type=simple
ExecStart=/usr/bin/dotrino-vaultd
Environment=DOTRINO_VAULT_DIR=%h/.local/share/dotrino/vault
Restart=always
RestartSec=5
KillSignal=SIGTERM
TimeoutStopSec=15
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
ReadWritePaths=%h/.local/share/dotrino
PrivateTmp=true
SyslogIdentifier=dotrino-vault

[Install]
WantedBy=default.target
UNIT
chmod 0644 "$STAGE/usr/lib/systemd/user/dotrino-vault.service"

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
Depends: systemd
Homepage: https://vault.dotrino.com
Installed-Size: $INSTALLED_KB
Description: Tu bóveda personal: toda tu información en un solo lugar seguro
 Guarda toda tu información —archivos, contactos, contrasenas y lo que usan tus
 apps— en una boveda dentro de tu propia computadora, no en la nube de una
 empresa. Privada, segura y tuya. Sin anuncios, sin rastreo. Software libre (MIT).
 .
 El binario trae todo embebido (no necesitas instalar nada mas). Corre como
 servicio de tu sesion y tus datos viven solo en tu cuenta.
CONTROL

# 5. post-install: habilitar la unidad de usuario para todos (arranca en el login)
cat > "$STAGE/DEBIAN/postinst" <<'POSTINST'
#!/bin/sh
set -e
systemctl daemon-reload 2>/dev/null || true
systemctl --global enable dotrino-vault.service >/dev/null 2>&1 || true
cat <<'MSG'

Dotrino Vault instalado.
  - Se inicia solo en tu proximo inicio de sesion.
  - Para iniciarlo ahora:     systemctl --user start dotrino-vault
  - Si estas ACTUALIZANDO, el servicio viejo sigue corriendo: reinicialo con
      systemctl --user restart dotrino-vault
  - Ver estado:               dotrino-vault status
  - Conectar un dispositivo:  dotrino-vault pair
Tus datos viven en ~/.local/share/dotrino/vault (solo tu los lees).

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
