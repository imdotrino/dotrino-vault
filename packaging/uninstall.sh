#!/usr/bin/env sh
# uninstall.sh — quita el servicio y los binarios de dotrino-vault.
#
# Por defecto CONSERVA tus datos (clave maestra, dispositivos, árbol) en
# ~/.local/share/dotrino/vault. Para borrarlos también:  sh uninstall.sh --purge
set -eu

BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
DATA_DIR="${XDG_DATA_HOME:-$HOME/.local/share}/dotrino/vault"

PURGE=0
[ "${1:-}" = "--purge" ] && PURGE=1

echo "dotrino-vault · desinstalando…"

# --- 1. parar + deshabilitar el servicio (idempotente) ------------------------
if command -v systemctl >/dev/null 2>&1; then
  systemctl --user stop dotrino-vault.service    >/dev/null 2>&1 || true
  systemctl --user disable dotrino-vault.service >/dev/null 2>&1 || true
  rm -f "$UNIT_DIR/dotrino-vault.service"
  systemctl --user daemon-reload >/dev/null 2>&1 || true
  echo "  servicio  → detenido y removido"
fi

# Nota: NO desactivamos linger por vos (podés tener otros servicios que lo usen).

# --- 2. binarios --------------------------------------------------------------
rm -f "$BIN_DIR/dotrino-vaultd" "$BIN_DIR/dotrino-vault"
echo "  binarios  → removidos de $BIN_DIR"

# --- 3. datos (solo con --purge) ---------------------------------------------
if [ "$PURGE" -eq 1 ]; then
  rm -rf "$DATA_DIR"
  echo "  datos     → BORRADOS ($DATA_DIR)"
  echo
  echo "ATENCIÓN: borraste tu clave maestra. Esa identidad no se puede recuperar."
else
  echo "  datos     → CONSERVADOS en $DATA_DIR"
  echo "              (para borrarlos:  sh uninstall.sh --purge)"
fi

echo "Listo."
