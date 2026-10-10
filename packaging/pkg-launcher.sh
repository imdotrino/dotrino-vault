#!/bin/sh
# pkg-launcher.sh — lo que el paquete del sistema (.deb / .rpm) deja en /usr/bin como
# `dotrino-vaultd` y `dotrino-vault`. No es la bóveda: la LANZA desde la carpeta de tu usuario.
#
# Por qué: la bóveda se instala como usuario para poder actualizarse sola (CONVENCIONES §15).
# Un binario en /usr/bin es de root y el servicio, que corre como tú, no puede cambiarlo. Así
# que el paquete trae el binario en /usr/lib/dotrino-vault y aquí se COPIA a
# ~/.local/share/dotrino/bin la primera vez; desde ahí corre y desde ahí se actualiza sola,
# igual que la instalación del tarball (install.sh).
#
# Cuándo se vuelve a copiar: solo si el paquete trae una versión MÁS NUEVA que la que tienes.
# Si la tuya ya se actualizó sola y va por delante del paquete, no se toca.
#
# La salida va en inglés, como la de los instaladores.
set -eu

PKG=/usr/lib/dotrino-vault
APP="$HOME/.local/share/dotrino/bin"
NAME="$(basename "$0")"
WANT="$(cat "$PKG/VERSION")"

seed () {
  mkdir -p "$APP"
  for f in dotrino-vaultd dotrino-vault; do
    # Al lado y renombrando encima: nunca queda un binario a medias, y el servicio que esté
    # corriendo ve el cambio y se reinicia solo con el nuevo.
    cp "$PKG/$f" "$APP/.$f.pkg"
    chmod 0755 "$APP/.$f.pkg"
    mv -f "$APP/.$f.pkg" "$APP/$f"
  done
  printf '%s\n' "$WANT" > "$APP/.pkg-version"
}

if [ ! -x "$APP/dotrino-vaultd" ] || [ ! -x "$APP/dotrino-vault" ]; then
  seed
elif [ "$(cat "$APP/.pkg-version" 2>/dev/null || true)" != "$WANT" ]; then
  # El paquete cambió desde la última vez que se miró. Se le pregunta su versión a la copia
  # del usuario; una que no sabe decirla está rota, y se dice antes de reponerla.
  HAVE="$("$APP/dotrino-vaultd" --ctl version 2>/dev/null | sed -n 's/^dotrino-vault //p')"
  if [ -z "$HAVE" ]; then
    echo "dotrino-vault: your copy in $APP does not start; replacing it with $WANT from the system package" >&2
    seed
  elif [ "$HAVE" != "$WANT" ] && [ "$(printf '%s\n%s\n' "$HAVE" "$WANT" | sort -V | tail -n 1)" = "$WANT" ]; then
    seed
  else
    printf '%s\n' "$WANT" > "$APP/.pkg-version"
  fi
fi

exec "$APP/$NAME" "$@"
