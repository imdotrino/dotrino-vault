#!/usr/bin/env sh
# install.sh — instalador idempotente de dotrino-vault (Linux, sin sudo).
#
# Qué hace:
#   1. copia el binario autosuficiente `dotrino-vaultd` (Node embebido) a ~/.local/bin
#   2. copia el CLI de control `dotrino-vault`
#   3. instala la unit systemd --user, la habilita y la arranca
#   4. activa linger para que el vault corra aunque no haya sesión iniciada
#   5. imprime el fingerprint para emparejar dispositivos
#
# Reejecutable sin efectos secundarios: actualiza binario + unit y reinicia.
#
# Uso:  sh install.sh        (desde el tarball descomprimido)
set -eu

# --- rutas XDG (con defaults) -------------------------------------------------
BIN_DIR="${XDG_BIN_HOME:-$HOME/.local/bin}"
UNIT_DIR="${XDG_CONFIG_HOME:-$HOME/.config}/systemd/user"
# Literal (no $XDG_DATA_HOME): debe coincidir con la unit (%h/.local/share) y con
# el default de paths.js (dataDir), o el CLI no halla al daemon. Para mover los
# datos usá DOTRINO_VAULT_DIR en la unit, no XDG_DATA_HOME.
DATA_DIR="$HOME/.local/share/dotrino/vault"
SRC="$(cd "$(dirname "$0")" && pwd)"

echo "dotrino-vault · instalando…"

# --- 0. comprobaciones --------------------------------------------------------
if ! command -v systemctl >/dev/null 2>&1; then
  echo "ERROR: no se encontró systemd (systemctl). v1 solo soporta Linux con systemd." >&2
  echo "       Podés arrancar el daemon a mano:  $BIN_DIR/dotrino-vaultd" >&2
  exit 1
fi

# --- 1. binario + CLI ---------------------------------------------------------
mkdir -p "$BIN_DIR"
install -m 0755 "$SRC/dotrino-vaultd" "$BIN_DIR/dotrino-vaultd"
install -m 0755 "$SRC/dotrino-vault"  "$BIN_DIR/dotrino-vault"
echo "  binario   → $BIN_DIR/dotrino-vaultd"
echo "  control   → $BIN_DIR/dotrino-vault"

# Aviso si ~/.local/bin no está en el PATH (no es fatal: el CLI es opcional).
case ":$PATH:" in
  *":$BIN_DIR:"*) : ;;
  *) echo "  NOTA: $BIN_DIR no está en tu PATH. Añadilo a ~/.profile para usar 'dotrino-vault'." ;;
esac

# --- 2. dir de datos (0700) ---------------------------------------------------
mkdir -p "$DATA_DIR"
chmod 700 "$DATA_DIR" 2>/dev/null || true

# --- 3. unit systemd --user ---------------------------------------------------
mkdir -p "$UNIT_DIR"
install -m 0644 "$SRC/dotrino-vault.service" "$UNIT_DIR/dotrino-vault.service"
echo "  servicio  → $UNIT_DIR/dotrino-vault.service"

# --- 4. linger: corre sin sesión iniciada (al boot) ---------------------------
# loginctl enable-linger normalmente NO pide sudo para el propio usuario.
if command -v loginctl >/dev/null 2>&1; then
  if loginctl enable-linger "$USER" >/dev/null 2>&1; then
    echo "  linger    → activado (el vault arranca en el boot, sin login gráfico)"
  else
    echo "  linger    → NO se pudo activar automáticamente."
    echo "              Ejecutá una vez:  sudo loginctl enable-linger $USER"
    echo "              (sin esto, el vault se detiene al cerrar sesión.)"
  fi
fi

# --- 5. enable + (re)start ----------------------------------------------------
systemctl --user daemon-reload
systemctl --user enable dotrino-vault.service >/dev/null 2>&1 || true
# restart cubre tanto primer arranque como actualización idempotente.
systemctl --user restart dotrino-vault.service

# --- 6. esperar primer arranque y mostrar el fingerprint ----------------------
echo
echo "dotrino-vault · esperando a que la identidad esté lista…"
i=0
while [ "$i" -lt 30 ]; do
  if [ -f "$DATA_DIR/state.json" ]; then break; fi
  i=$((i + 1))
  sleep 1
done

echo
if "$BIN_DIR/dotrino-vault" status 2>/dev/null; then
  :
else
  echo "El servicio está arrancando. Revisá el estado con:  dotrino-vault status"
fi

cat <<EOF

Listo. El vault corre como servicio y se reinicia solo / arranca en el boot.

  Estado:        dotrino-vault status
  Logs en vivo:  journalctl --user -u dotrino-vault -f
  Emparejar:     dotrino-vault pair        (muestra QR para tu teléfono/laptop)
  Desinstalar:   sh uninstall.sh

Tus datos (clave maestra incluida) viven en:
  $DATA_DIR   (permisos 0600/0700, en claro en v1)
EOF
