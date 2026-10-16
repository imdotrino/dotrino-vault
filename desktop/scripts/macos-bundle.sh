#!/bin/sh
# Arma «Dotrino Vault.app»: la ventana (`dotrino-vault-desktop`) y la bóveda (`dotrino-vaultd`,
# el binario SEA de packaging/build-mac.sh) juntas en Contents/MacOS, que es donde la ventana
# busca la bóveda. Lo comprime con la versión en el nombre (CONVENCIONES §11.5).
# Se corre en macOS (hacen falta iconutil, sips, codesign y ditto).
#   desktop/scripts/macos-bundle.sh <ventana> <bóveda>
set -eu
cd "$(dirname "$0")/.."
GUI=$1
VAULTD=$2
VERSION=$(node -p "require('../package.json').version")
APP="dist/Dotrino Vault.app"
rm -rf dist && mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
cp "$GUI" "$APP/Contents/MacOS/dotrino-vault-desktop"
cp "$VAULTD" "$APP/Contents/MacOS/dotrino-vaultd"
ICONSET=dist/icon.iconset && mkdir -p "$ICONSET"
for s in 16 32 128 256 512; do
  sips -z $s $s assets/icon-512.png --out "$ICONSET/icon_${s}x${s}.png" >/dev/null
  d=$((s * 2)); [ $d -le 512 ] && sips -z $d $d assets/icon-512.png --out "$ICONSET/icon_${s}x${s}@2x.png" >/dev/null
done
iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/icon.icns"
cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleName</key><string>Dotrino Vault</string>
  <key>CFBundleDisplayName</key><string>Dotrino Vault</string>
  <key>CFBundleIdentifier</key><string>com.dotrino.vault.desktop</string>
  <key>CFBundleExecutable</key><string>dotrino-vault-desktop</string>
  <key>CFBundleIconFile</key><string>icon</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$VERSION</string>
  <key>CFBundleVersion</key><string>$VERSION</string>
  <key>LSMinimumSystemVersion</key><string>12.0</string>
  <key>NSHighResolutionCapable</key><true/>
</dict></plist>
PLIST
# Firma ad hoc del conjunto: sin ella, en arm64 el binario no arranca. No es la firma de un
# desarrollador de Apple: Gatekeeper avisa la primera vez.
codesign --sign - --force --deep "$APP"
(cd dist && ditto -c -k --keepParent "Dotrino Vault.app" "dotrino-vault-$VERSION-macos-universal.zip")
echo "dist/dotrino-vault-$VERSION-macos-universal.zip"
