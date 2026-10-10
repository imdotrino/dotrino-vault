#!/usr/bin/env bash
# build-rpm.sh — empaqueta dotrino-vault como paquete RPM (.rpm) para x86_64
# (Fedora, RHEL y derivadas, openSUSE).
#
# Es el hermano de build-deb.sh y deja lo mismo: binarios en /usr/bin y la UNIDAD DE
# USUARIO en /usr/lib/systemd/user/, habilitada para todos los usuarios
# (`systemctl --global enable`). Cada usuario tiene su bóveda en ~/.local/share/dotrino/vault.
#
# Requiere: rpmbuild (en Debian/Ubuntu: `apt install rpm`; en Fedora: `dnf install rpm-build`).
# Usa el binario de packaging/build.sh (lo construye si falta o si es de otra versión).
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$(pwd)"
DIST="$ROOT/dist"
VER="$(node -p "require('$ROOT/package.json').version")"

command -v rpmbuild >/dev/null 2>&1 || { echo "ERROR: rpmbuild not found (Debian/Ubuntu: apt install rpm · Fedora: dnf install rpm-build)" >&2; exit 1; }

# 1. binario autosuficiente (Node embebido), de ESTA versión — misma comprobación que el .deb
BUILT="$(cat "$DIST/.built-version" 2>/dev/null || echo '')"
if [ ! -f "$DIST/dotrino-vaultd" ] || [ "$BUILT" != "$VER" ]; then
  echo "==> el binario de dist/ es «${BUILT:-ninguno}» y toca «$VER»: reconstruyéndolo (build.sh)…"
  bash "$ROOT/packaging/build.sh"
fi

TOP="$(mktemp -d)"
trap 'rm -rf "$TOP"' EXIT
mkdir -p "$TOP/SPECS" "$TOP/SRC"
cp "$DIST/dotrino-vaultd" "$DIST/dotrino-vault" "$ROOT/README.md" "$TOP/SRC/"
cp "$ROOT/packaging/dotrino-vault.system.service" "$TOP/SRC/dotrino-vault.service"

# 2. el spec. Tres cosas que NO son adorno:
#
#   · NADA de strip ni de post-proceso (`__os_install_post`): el binario es un Node con el
#     programa inyectado dentro (SEA). Pasarle `strip` lo deja arrancando como un Node pelado,
#     sin la bóveda — un paquete que instala bien y no hace nada.
#   · `AutoReqProv: no`: las dependencias se escriben a mano. Si no, salen de la máquina que
#     empaqueta (Ubuntu en CI) y no de la que instala.
#   · `libatomic.so.1()(64bit)` y no un nombre de paquete: se llama `libatomic` en Fedora y
#     `libatomic1` en openSUSE; la librería se llama igual en las dos.
cat > "$TOP/SPECS/dotrino-vault.spec" <<SPEC
%global debug_package %{nil}
%global __os_install_post %{nil}
%global __strip /bin/true
%global _build_id_links none
%define _binary_payload w6.xzdio
%define _binary_filedigest_algorithm 8
%define _source_filedigest_algorithm 8

Name:           dotrino-vault
Version:        $VER
Release:        1
Summary:        Your personal vault: all your information in one safe place
License:        MIT
URL:            https://vault.dotrino.com
Packager:       Dotrino <hola@dotrino.com>
AutoReqProv:    no
Requires:       systemd
Requires:       libatomic.so.1()(64bit)
Suggests:       fido2-tools

%description
Keep all your information -files, contacts, passwords and whatever your apps
use- in a vault inside your own computer, not in a company's cloud. Private,
secure and yours. No ads, no tracking. Free software (MIT).

The binary bundles everything (nothing else to install). It runs as a service
of your session and your data lives only in your account.

%install
rm -rf %{buildroot}
install -D -m0755 $TOP/SRC/dotrino-vaultd        %{buildroot}/usr/bin/dotrino-vaultd
install -D -m0755 $TOP/SRC/dotrino-vault         %{buildroot}/usr/bin/dotrino-vault
install -D -m0644 $TOP/SRC/README.md             %{buildroot}/usr/share/doc/dotrino-vault/README.md
install -D -m0644 $TOP/SRC/dotrino-vault.service %{buildroot}/usr/lib/systemd/user/dotrino-vault.service

%files
%attr(0755,root,root) /usr/bin/dotrino-vaultd
%attr(0755,root,root) /usr/bin/dotrino-vault
%attr(0644,root,root) /usr/lib/systemd/user/dotrino-vault.service
%dir %attr(0755,root,root) /usr/share/doc/dotrino-vault
%attr(0644,root,root) /usr/share/doc/dotrino-vault/README.md

%post
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

%postun
# \$1 = 0 solo al DESINSTALAR; en una actualización vale 1 y la unidad se queda habilitada.
if [ "\$1" = "0" ]; then
  systemctl --global disable dotrino-vault.service >/dev/null 2>&1 || true
fi
exit 0
SPEC

# 3. construir. El nombre lleva la versión (CONVENCIONES §11.5).
rpmbuild -bb --target x86_64 \
  --define "_topdir $TOP" \
  --define "_rpmdir $TOP/RPMS" \
  --define "_build_name_fmt %%{NAME}-%%{VERSION}-%%{RELEASE}.%%{ARCH}.rpm" \
  "$TOP/SPECS/dotrino-vault.spec" >"$TOP/rpmbuild.log" 2>&1 || { cat "$TOP/rpmbuild.log" >&2; exit 1; }

OUT="$DIST/dotrino-vault-${VER}-1.x86_64.rpm"
cp "$TOP/RPMS/dotrino-vault-${VER}-1.x86_64.rpm" "$OUT"

echo "OK -> $OUT  ($(du -h "$OUT" | cut -f1))"
