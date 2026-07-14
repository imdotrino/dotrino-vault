# @dotrino/vault

Usa **este dispositivo (navegador) como bóveda/CA** del ecosistema Dotrino, sin un PC
con el daemon. Es la contraparte browser del daemon `dotrino-vault`: atiende el mismo
protocolo de enrolamiento endurecido por el proxy y firma certificados de delegación
`D ← P` (donde `P` es la identidad de este dispositivo, `@dotrino/identity`).

Pensado para que **cualquier app** del ecosistema (no solo la terminal) pueda ofrecer
"usar este dispositivo como bóveda".

## Uso

```js
import { Identity } from '@dotrino/identity'
import { startDeviceVault } from '@dotrino/vault'

const identity = await Identity.connect()
const vault = await startDeviceVault(identity)          // se conecta al proxy como P

// 1) Abrir un emparejamiento y mostrar el QR/JSON al dispositivo a enrolar:
const { qr } = vault.startPairing({ label: 'mi-agente' })
// El dispositivo (p. ej. @dotrino/identity#enrollDevice) consume `qr`, GENERA un
// código aleatorio y lo MUESTRA (no lo envía).

// 2) Cuando el dispositivo pide acceso, aparece en la lista de pendientes:
vault.onPendingChange(() => {
  for (const { deviceId } of vault.listPending()) {
    // Un humano LEE el código del dispositivo y lo TIPEA aquí:
    // await vault.approve(deviceId, codigoTipeado)
  }
})

// 3) Máquinas ya enroladas / revocar:
const machines = await vault.listMachines()   // [{ sub, deviceId, label, exp, nonce, scope }]
// await vault.revoke(nonce)

vault.close()
```

## Credenciales del vault en vez del `.env` (Node)

La cara "dotenv" del paquete: **cualquier proyecto Node** jala sus credenciales del
vault del dueño y las deja en `process.env`. En el disco del servicio **no queda
ningún secreto**: solo la llave del dispositivo (generada ahí, nunca sale) y un
certificado con scope `vault:secrets:<ns>`. Los valores viven **solo en memoria**;
si la máquina se compromete, revocas el cert y no había nada que robar.

### 1) Registro del cliente (una sola vez)

```bash
# en el VAULT (tu PC): abres el emparejamiento del servicio y cargas sus secretos
dotrino-vault pair --service miapp          # invitación con scope SOLO vault:secrets:miapp
dotrino-vault secret set miapp API_KEY  sk-…

# en el PROYECTO/servidor: enrola esta máquina (pega la invitación)
npx dotrino-env enroll --ns miapp
#   → muestra un código:  dotrino-vault approve 7K3F-92Q1

# de vuelta en el VAULT: lo tipeas leyéndolo de esa pantalla
dotrino-vault approve 7K3F-92Q1
```

El código lo **genera el servicio** y **no viaja** por la red: el vault solo puede
echarlo de vuelta si un humano lo tipeó. Así, un vault falso no puede enrolarte y
aprobar a ciegas no enrola a nadie. Queda `~/.dotrino/service/<ns>/service-identity.json`
(0600) con `{ device, cert, iss, proxy, ns }`.

Es un **comando previo**, no el primer arranque de la app: el enrolamiento necesita a
un humano leyendo el código en esta pantalla (bajo systemd/PM2 no hay TTY y el código
acabaría en un log), bloquea esperando la aprobación y **escribe** en disco consumiendo
una invitación de un solo uso. El arranque, en cambio, solo **lee** la identidad ya
guardada: es idempotente y no interactúa con nadie. Corre el `enroll` donde corres el
`npm ci` al aprovisionar la máquina.

### 2) En el código

```js
import '@dotrino/vault/config'    // como `dotenv/config`, pero contra el vault (ns = DOTRINO_NS)
console.log(process.env.API_KEY)
```

o explícito:

```js
import { loadEnv } from '@dotrino/vault/env'
const { secrets } = await loadEnv({ ns: 'miapp', required: ['API_KEY'] })
```

Es **asíncrono a propósito**: el `import` bloquea el arranque (top-level await) hasta
que los secretos estén. Si el vault no está disponible, **espera** (reintento con
backoff) — un servicio sin vault no arranca, no opera con secretos viejos ni vacíos.
Un fallo NO transitorio (sin enrolar, cert revocado, scope equivocado) sí aborta.

Para procesos que no son Node, el CLI los inyecta en el entorno de un hijo:

```bash
dotrino-env run --ns miapp -- ./mi-binario
```

### API `@dotrino/vault/env`

- `loadEnv({ ns?, dir?, override?, wait?, required?, onRetry? }) → { ns, secrets, injected, skipped }`
  (por defecto **no pisa** variables ya presentes en el entorno; `override: true` sí)
- `serviceDir(ns)`, `serviceRoot()`, `listEnrolled()`, `resolveNs(ns?)`
- Entorno: `DOTRINO_NS` · `DOTRINO_ENV_DIR` · `DOTRINO_ENV_HOME` · `DOTRINO_ENV_QUIET`
- CLI: `dotrino-env enroll|status|check|run`  (`check` lista **nombres** de secretos, nunca valores)

Bajo el capó es `@dotrino/vault/service` (`enrollService` / `waitForSecrets`): petición
firmada por la llave del servicio + cert, respuesta **sellada** (ECDH efímero + AES-GCM,
el proxy no ve los valores) y **firmada por la maestra**, verificada contra la `iss`
pineada en el enrolamiento.

## Modelo de aprobación (seguro por diseño)

- El **dispositivo** que se enrola genera un **código aleatorio** (`makePairingCode`) y
  lo **muestra**; el código **no viaja** por la red.
- Esta bóveda **no conoce** el código: un humano lo **lee del dispositivo** y lo **tipea**
  aquí. Al aprobar, la bóveda firma el cert y **echa** el código tipeado de vuelta.
- El dispositivo acepta el cert **solo si el código echado coincide** con el que generó.
  Así, una bóveda falsa (que nunca vio el código) no puede enrolarlo, y **aprobar a ciegas**
  (sin ir a leer el código del dispositivo) no enrola a nadie.

## API

`startDeviceVault(identity, { proxyUrl? }) → Promise<handle>`

- `startPairing({ scope?, ttlMs?, label? }) → { qr, expiresInMs }`
- `listPending() → [{ deviceId, label }]`
- `approve(deviceId, code) → Promise<{ ok, deviceId }>`  (code = lo que muestra el dispositivo)
- `reject(deviceId)`
- `listMachines() → Promise<[{ sub, deviceId, label, scope, exp, nonce }]>`
- `revoke(nonce) → Promise`
- `getSelfCert() → Promise<cert>`  (self-cert `P ← P`, para actuar además de cliente)
- `onPendingChange(fn)`, `close()`

Cripto y firma: `@dotrino/identity`. Transporte: `@dotrino/proxy-client`. No reimplementa
nada del ecosistema.

MIT · parte de [Dotrino](https://dotrino.com).
