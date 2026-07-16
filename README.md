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

### Varios perfiles en el mismo PC

Puedes tener varias identidades tuyas en la misma máquina (p. ej. personal y
trabajo). Cada perfil es **una identidad distinta**: su propia clave, sus propios
dispositivos, sus propios datos y secretos — nada se cruza entre ellos. **Todos
atienden a la vez**: el perfil «activo» solo decide a cuál va un comando cuando no
lo dices con `--profile`, no apaga a los demás.

```sh
dotrino-vault profile ls                  # lista los perfiles (* = el activo)
dotrino-vault profile add Trabajo         # crea un perfil (identidad nueva, vacía)
dotrino-vault profile use Trabajo         # elige el activo
dotrino-vault profile rename <nombre>     # renombra
dotrino-vault profile rm Trabajo          # BORRA el perfil y su identidad (irreversible)

dotrino-vault pair --profile Trabajo      # cualquier comando acepta --profile
dotrino-vault devices --profile personal
```

Si ya usabas el vault antes de esto, tu identidad de siempre se convierte sola en
el primer perfil («Perfil 1»): la misma clave, los mismos dispositivos, nada que
volver a emparejar.

### Contraseña del perfil (opcional)

Cada perfil puede llevar contraseña. **Solo se pide para EDITAR el perfil** (cambiar
tu nombre, avatar o datos): tus dispositivos siguen firmando, leyendo y guardando
aunque el perfil esté bloqueado — así un reinicio del PC nunca deja tus apps
muertas esperando a que alguien teclee algo.

```sh
dotrino-vault profile password     # pone o cambia la contraseña (te la pregunta)
dotrino-vault profile password rm  # la quita
dotrino-vault unlock               # desbloquea para poder editar
dotrino-vault lock                 # vuelve a bloquear
```

El perfil se vuelve a bloquear al reiniciar el servicio. La contraseña **no se
guarda**: solo un verificador con sal (PBKDF2), igual que el candado del navegador.
Para que quede claro qué protege y qué no: evita que otro que se siente en tu
máquina —o un dispositivo tuyo comprometido— te reescriba el perfil; **no** cifra la
clave en el disco (eso es el cifrado en reposo, ver *Alcance*).

**Emparejamiento endurecido** (ver [`docs/pairing-protocol.md`](./docs/pairing-protocol.md)):
el dispositivo prueba posesión de su llave firmando el enrolamiento, y la maestra
solo firma el certificado **después** de que compares un código de 6 dígitos (SAS)
entre las dos pantallas y corras `approve`. Un código robado ya no alcanza para
entrar; la revocación de un dispositivo le ordena **autoborrarse** (con firma de la
maestra, no por un mensaje cualquiera).

El servicio se gestiona con systemd `--user`
(`systemctl --user {start,stop,restart} dotrino-vault`). Tus datos —clave maestra
incluida— viven en `~/.local/share/dotrino/vault` (permisos `0600`/`0700`), con un
subdirectorio `p/<id>/` por perfil.

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
`vault:secrets:<ns>` (`pair --service <ns>`), y al arrancar piden su bundle.

Son **dos momentos distintos, a propósito**: el **enrolamiento** (registro de la
máquina) es un **comando previo** que corre un humano **una sola vez**; el
**arranque** de la app solo lee la identidad ya guardada y no interactúa con nadie.

#### 1) Enrolamiento — comando previo, una vez por máquina

```bash
# en el VAULT (tu PC)
dotrino-vault pair --service proxy                 # invitación con scope SOLO vault:secrets:proxy
dotrino-vault secret set proxy TURN_KEY_ID  …

# en la MÁQUINA del servicio (pega la invitación; te MUESTRA un código)
npx dotrino-env enroll --ns proxy

# de vuelta en el VAULT: tipeas el código LEYÉNDOLO de la pantalla del servicio
dotrino-vault approve 7K3F-92Q1
```

Deja `~/.dotrino/service/<ns>/service-identity.json` (0600) con la llave del
dispositivo (generada ahí, nunca sale) + el cert. **No hay ningún secreto en disco.**

**Por qué NO se enrola en el primer arranque de la app:** el enrolamiento exige un
humano que **lea el código en la pantalla del servicio** — es lo único que impide que
un vault falso (que nunca vio el código) enrole la máquina, o que alguien apruebe a
ciegas. Un servicio arranca bajo systemd/PM2, sin TTY y sin nadie mirando: el código
acabaría en un log (y quien lea el log ya podría aprobar). Además el arranque quedaría
bloqueado esperando una aprobación que quizá nadie da, y un reinicio automático de
madrugada intentaría re-enrolar. Separados, el arranque es determinista e idempotente:
solo **lee**; el enrolamiento **escribe** y consume una invitación de un solo uso.

Va donde va el `npm ci` al aprovisionar el VPS. (Para máquinas efímeras —Docker,
autoescalado— haría falta una invitación pre-provisionada de un solo uso con TTL corto
y auto-aprobación; **aún no está decidido ni implementado**.)

#### 2) Arranque — sin interacción, en cada reinicio

```js
import '@dotrino/vault/config'     // como `dotenv/config`, pero contra el vault (ns = DOTRINO_NS)
console.log(process.env.TURN_KEY_ID)
```

o explícito, con `@dotrino/vault/env` / `@dotrino/vault/service`:

```js
import { loadEnv } from '@dotrino/vault/env'
const { secrets } = await loadEnv({ ns: 'proxy', required: ['TURN_KEY_ID'] })
```

**Modos de fallo (importante):**

- **Vault caído / proxy caído** → **espera** (reintento con backoff, para siempre). Sin
  vault el servicio no opera: no arranca con secretos viejos ni vacíos.
- **Sin enrolar, cert revocado o vencido, scope equivocado** → **aborta en el acto**.
  Son errores que no se arreglan reintentando: hay que (re)enrolar.

CLI de apoyo: `dotrino-env status` (qué hay enrolado aquí), `dotrino-env check` (lista
los **nombres** de los secretos, nunca los valores), `dotrino-env run -- <cmd>` (inyecta
los secretos en el entorno de un proceso que no es Node).

Garantías: la petición va firmada por la llave del servicio + cert (scope solo
su `ns`); la respuesta viaja **sellada** a una llave efímera por petición (el
proxy que la transporta no puede leerla, y un replay no se puede descifrar) y
**firmada por la maestra** (verificada contra la `iss` pineada del enrolamiento).
Revocar el cert (`revoke`) corta el acceso de inmediato; `activity` audita cada
lectura. Los servicios críticos sin secretos en su core (el propio proxy) arrancan
sin vault; solo la feature que los necesita (TURN) espera. Primer consumidor:
`dotrino-proxy` (TURN de Cloudflare, ver su README).

## Alcance

- **v1 (este):** servicio headless en Node (Linux), **multi-perfil**, con
  **contraseña opcional por perfil para editarlo** (verificador PBKDF2) pero la
  **clave privada en claro** en el disco (en `~/.local/share/dotrino/vault`, permisos
  `0600`). Enrolamiento de dispositivos, firma delegada y lectura del árbol de
  contenidos por el proxy. Distribución como binario único (Node SEA) + servicio systemd.
- **v2:** **cifrado en reposo** con la contraseña (keychain del SO o archivo, a
  elección) — hoy la contraseña es un candado de edición, no cifra la clave; UI de
  escritorio (Tauri) como cliente del daemon; firma de documentos con sellado de
  tiempo (`dotrino-signer`); macOS y Windows.

## Estructura

- `src/vault.js` — núcleo de UN perfil (Identity + transporte + router: enrolar/firmar/leer).
- `src/profiles.js` — registro multi-perfil (`profiles.json`, `p/<id>/`) + candado por contraseña.
- `src/manager.js` — corre todos los perfiles a la vez (uno por maestra/conexión).
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
