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
dotrino-vault status               # estado del servicio + fingerprint
dotrino-vault pair                 # inicia un emparejamiento (muestra el código y espera al dispositivo)
dotrino-vault pending              # muestra el dispositivo pendiente + su código a comparar
dotrino-vault approve <deviceId>   # aprueba un dispositivo (tras comparar el código en ambas pantallas)
dotrino-vault reject  <deviceId>   # rechaza un dispositivo pendiente
dotrino-vault devices              # lista dispositivos enrolados / revocados
dotrino-vault revoke  <nonce>      # revoca un dispositivo (le ordena autoborrarse)
dotrino-vault pair --service <ns>  # empareja un SERVICIO (proxy, geo…) con acceso SOLO a sus secretos
dotrino-vault secret set <ns> <CLAVE> <valor>   # guarda un secreto para ese servicio
dotrino-vault secret rm  <ns> <CLAVE>           # borra un secreto
dotrino-vault secret list                       # nombres de secretos (nunca valores)
dotrino-vault logs                 # últimos logs del servicio
```

**Emparejamiento endurecido** (ver [`docs/pairing-protocol.md`](./docs/pairing-protocol.md)):
el dispositivo prueba posesión de su llave firmando el enrolamiento, y la maestra
solo firma el certificado **después** de que compares un código de 6 dígitos (SAS)
entre las dos pantallas y corras `approve`. Un código robado ya no alcanza para
entrar; la revocación de un dispositivo le ordena **autoborrarse** (con firma de la
maestra, no por un mensaje cualquiera).

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

### Secretos de servicios (los servicios del ecosistema son clientes identificados)

Los servicios (proxy, geo, bots…) **no llevan secretos de terceros en su `.env`**:
se enrolan al vault como un dispositivo más, con un cert limitado al scope
`vault:secrets:<ns>` (`pair --service <ns>`), y al arrancar piden su bundle con
`@dotrino/vault/service`:

```js
import { enrollService, waitForSecrets } from '@dotrino/vault/service'

// una vez (con el payload del QR de `pair --service proxy`):
await enrollService({ qr, ns: 'proxy', dir: './vault-service' })

// en cada arranque: espera al vault PARA SIEMPRE (sin vault, la feature no opera)
const secrets = await waitForSecrets({ dir: './vault-service' })
// → { TURN_KEY_ID: '…', TURN_KEY_API_TOKEN: '…' }
```

Garantías: la petición va firmada por la llave del servicio + cert (scope solo
su `ns`); la respuesta viaja **sellada** a una llave efímera por petición (el
proxy que la transporta no puede leerla, y un replay no se puede descifrar) y
**firmada por la maestra** (verificada contra la `iss` pineada del enrolamiento).
Revocar el cert (`revoke`) corta el acceso de inmediato; `activity` audita cada
lectura. Los servicios críticos sin secretos en su core (el propio proxy) arrancan
sin vault; solo la feature que los necesita (TURN) espera. Primer consumidor:
`dotrino-proxy` (TURN de Cloudflare, ver su README).

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
