# Dotrino Vault — tu certificador personal

> **Parte del ecosistema [Dotrino](https://dotrino.com).** Tu identidad, en tu
> máquina, bajo tus reglas — sin anuncios, sin cookies, sin rastreo.

`dotrino-vault` es el **certificador personal** del usuario: un **servicio headless**
que custodia tu **clave maestra** y actúa como tu **propia CA**. En vez de depender
de las CAs, del "Inicia sesión con Google/Apple" o de verificadores de KYC, **tú
certificas**: enrolas tus dispositivos, firmas documentos y avalas a otras personas,
sin pedirle permiso a ningún portero central. La maestra **nunca sale** de tu máquina.

## Modelo: identidad delegada (la maestra se queda en una sola máquina)

```
 PC (vault)  ── clave maestra P (NUNCA sale) ────────────────────────────┐
   · genera/custodia P (vía @dotrino/identity)                            │
   · firma un CERT por dispositivo:  "D puede <scope> en nombre de P,     │
     hasta <exp>, revocable por <nonce>"                                  │
   · firma datos a pedido de un dispositivo enrolado (devuelve solo la firma)
         ▲ proxy (sendByPubkey + cola offline 24h)                        │
         │                                                                │
   cel / laptop  ── su propia sub-clave D (P nunca la ve) ────────────────┘
     · se enrola escaneando un QR del vault → recibe su cert
     · firma cada acción con D y adjunta el cert; el vault verifica la CADENA D←P
```

Todo esto **no se reimplementa**: la cripto de delegación vive en
`@dotrino/identity` (`signDelegation`, `verifyChain`, `makeDeviceKey`), el transporte
es `@dotrino/proxy-client`. Este repo solo **orquesta**.

## Instalación (Linux)

**Ubuntu / Debian — `.deb`** (lo más simple): descarga el `.deb` (versionado) desde
[Releases](https://github.com/imdotrino/dotrino-vault/releases/latest) y haz doble
clic, o en la terminal:

```sh
sudo apt install ./dotrino-vault_*.deb
```

**Otro Linux — tarball:** descarga el binario autosuficiente y ejecuta el instalador:

```sh
tar xzf dotrino-vault-*-linux-x64.tar.gz
cd dotrino-vault-*-linux-x64
sh install.sh
```

El `.deb` deja los binarios en `/usr/bin`, instala la unidad `systemd --user` y la
habilita; el tarball hace lo equivalente en tu `$HOME`. Ambos: nada de Node ni
dependencias, y el servicio arranca solo.

El binario **trae Node embebido**: no necesitas instalar nada más. El instalador lo
deja como **servicio systemd `--user`** que arranca solo (también en el boot, vía
`linger`). En el primer arranque genera tu identidad y se conecta al proxy. **Sin
contraseña, sin abrir puertos** (el vault marca hacia afuera).

> Sin firma de código: tu sistema puede advertir que el binario no está firmado. Es
> autohospedado y de código abierto; en Linux solo necesita permiso de ejecución (el
> instalador lo da). macOS y Windows llegan en v2.

### CLI de control

```sh
dotrino-vault status            # estado del servicio + fingerprint
dotrino-vault pair              # muestra un QR para enrolar un dispositivo
dotrino-vault devices           # lista dispositivos enrolados / revocados
dotrino-vault revoke <nonce>    # revoca un dispositivo
dotrino-vault logs              # últimos logs del servicio
```

El servicio se gestiona con systemd `--user`
(`systemctl --user {start,stop,restart} dotrino-vault`). Tus datos —clave maestra
incluida— viven en `~/.local/share/dotrino/vault` (permisos `0600`/`0700`).

## Desarrollo

```sh
npm install
node bin/dotrino-vaultd.js          # arranca el daemon (modo servicio)
node bin/dotrino-vaultd.js --pair   # arranca + imprime un QR de emparejamiento
bash packaging/build.sh             # compila el binario único (dist/)
```

### Enrolar y usar desde un dispositivo (Node, para testing)

```js
import { enroll, requestSign } from 'dotrino-vault/src/client.js'

// 1) escaneas el QR del vault → obtienes { iss, proxy, token }
const { device, cert, iss } = await enroll({ qr })   // GUARDA device (privada) + cert

// 2) le pides a la maestra que firme algo (la maestra nunca sale del vault)
const { signature } = await requestSign({
  masterPubkey: iss, proxyUrl: qr.proxy, device, cert,
  payload: { hola: 'mundo' }
})
```

## Alcance

- **v1 (este):** servicio headless en Node (Linux), **sin contraseña maestra**,
  **clave privada en claro** (en `~/.local/share/dotrino/vault`, permisos `0600`).
  Enrolamiento de dispositivos, firma delegada y lectura del árbol de contenidos por
  el proxy. Distribución como binario único (Node SEA) + servicio systemd.
- **v2:** contraseña maestra opcional → cifrado en reposo (keychain del SO o archivo,
  a elección); UI de escritorio (Tauri) como cliente del daemon; firma de documentos
  con sellado de tiempo (`dotrino-signer`); macOS y Windows.

## Estructura

- `src/vault.js` — núcleo (Identity + transporte + router de pedidos: enrolar/firmar/leer).
- `src/daemon.js` — modo servicio: `state.json`, emparejamiento por señal, apagado limpio.
- `src/ctl.js` — CLI de control (habla con el daemon por archivos + señales, sin socket).
- `src/transport.js` — conexión headless al proxy + `identify` firmado.
- `src/store.js` — árbol de contenidos (`vault.json`, versionado).
- `src/client.js` — helper de **dispositivo** (enrolar / pedir firma / leer).
- `src/protocol.js` — tipos de mensaje y scopes. · `src/qr.js` — QR ASCII. · `src/paths.js` — dirs.
- `bin/sea-entry.js` — entrypoint del binario único (multicall daemon / `--ctl`).
- `bin/dotrino-vaultd.js` — entrypoint de desarrollo (node directo).
- `packaging/` — `build.sh` (binario), `install.sh`/`uninstall.sh`, unit systemd.
- `web/` — la página `vault.dotrino.com` (Vite + Vue).

Sin anuncios, sin cuentas, sin rastreo. MIT · parte de Dotrino.
