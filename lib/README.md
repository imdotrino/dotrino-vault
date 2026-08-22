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
dotrino-vault secret set miapp API_KEY  sk-…   # la comparten TODAS las máquinas del ns

# en el PROYECTO/servidor: enrola esta máquina (pega la invitación)
npx dotrino-env enroll --ns miapp
#   → muestra un código:  dotrino-vault approve 7K3F-92Q1

# de vuelta en el VAULT: lo tipeas leyéndolo de esa pantalla
dotrino-vault approve 7K3F-92Q1
```

Si la misma app corre en **varias máquinas**, lo que cambia de una a otra (el puerto,
la URL pública) va en el cajón **por aparato**, sin partir el `ns`:

```bash
dotrino-vault devices                                   # el ID del aparato: AB12-CD34
dotrino-vault secret device set AB12-CD34 PORT 8443     # solo la lee ESA máquina
```

Llegan **mezcladas en el mismo bundle** —y por lo tanto en el mismo `process.env`—:
las del scope, con las del aparato **encima** si se llaman igual.

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

#### Esperar al vault es la REGLA. La excepción es una sola

Un agente enrolado **espera**. No es una preferencia: arrancar igual significaría
operar con la configuración vieja del `.env`, que es justo lo que el vault vino a
dejar de ser. Y la espera casi nunca duele, porque estos agentes no son críticos:
que un bot o un firmador tarden en levantar no rompe a nadie.

La **única** excepción conocida es **el proxio**, y no por importancia sino por una
razón estructural: el vault habla con sus servicios **por el proxio**. Un proxio que
espera al vault espera a alguien que necesita que el proxio ya esté escuchando —
abrazo mortal, y con él se cae el vault de todo el mundo. Por eso el proxio arranca
con lo que tenga y aplica la configuración cuando llega, con `applyEnv`.

> `applyEnv` existe **para ese caso**, no como alternativa cómoda al bloqueo. Si tu
> agente no está en el camino por el que viaja el propio vault, usa
> `import '@dotrino/vault/config'` y deja que espere. El precio de la excepción es
> real: lo que sólo se lee al arrancar llega tarde y no toma efecto hasta reiniciar,
> así que hay que avisarlo en el log — el proxio lo hace.

Para procesos que no son Node, el CLI los inyecta en el entorno de un hijo:

```bash
dotrino-env run --ns miapp -- ./mi-binario
```

### Un agente tiene UNA identidad, y se la da el vault

Un **aparato** puede llevar varios perfiles, y hasta meter su propia cuenta al vault
por adopción: llega con una historia que conservar. Un **agente** no es eso. Es un
servicio: su identidad se la cede el vault y no hay caso en que quiera empujar la
suya hacia arriba. De ahí tres reglas, que el paquete aplica solas:

- **No adopta, nunca.** La invitación declara su modo (`join` / `adopt`); si viene
  abierta para adoptar, `enrollService` la **rechaza al pegarla**, sin salir a la red.
  La intención `join` va además firmada dentro de la petición, para que nadie en el
  medio la convierta en otra cosa.
- **No acumula.** Enrolar de nuevo **reemplaza** la identidad anterior, que deja de
  existir en ese agente. No es un error a desbloquear con `--force`: es la forma de
  **rotar** la identidad de un agente comprometido. Se avisa por `onReplace` qué se
  descarta.
- **Un agente, un `ns`.** Varios agentes pueden convivir en una máquina (un
  directorio por namespace); lo que no existe es un agente que sea varios.

> ⚠ Si esa llave es además la **identidad de red** del servicio —el caso del proxio,
> cuyo id de nodo se deriva de ella— reemplazarla le cambia el nombre en la red: las
> instancias y citas vivas dejan de resolver y los peers que lo tenían pineado lo
> rechazan hasta re-pinearlo. Es a propósito: así se echa a un nodo comprometido.

### Rotar: la bóveda avisa y el agente SE REINICIA

Cambiar un secreto en la bóveda no sirve de nada si quien lo usa no se entera. Al
guardar, la bóveda manda un **aviso firmado** a los agentes de ese `ns` (sin
valores: sólo dice que cambió), **agrupando** las escrituras seguidas para que
cargar cinco valores no provoque cinco reinicios.

El agente **no recarga en caliente: termina**, y lo levanta su supervisor (pm2,
systemd `Restart=always`). Con `import '@dotrino/vault/config'` ya viene puesto.

Salir en vez de recargar, por tres razones — y la primera es la de peso:

1. **Borra de memoria el valor viejo.** En JavaScript un secreto no se puede
   borrar: los strings son inmutables, no hay `zeroize`, y el valor sigue en el
   heap hasta que al recolector le apetezca, más lo que capturó cada *closure* y
   cada caché derivada. Una llave se rota casi siempre **porque se filtró**, así
   que dejarla viva en el proceso anula el motivo de rotarla. Un proceso nuevo
   empieza con el heap limpio.
2. **Lee todo fresco.** Recargar en caliente exige que cada sitio que leyó una
   variable sepa releerla; esa lista hay que mantenerla para siempre y, cuando se
   queda corta, falla en silencio.
3. **Es un interruptor de emergencia.** Revocar el cert de un agente ya no espera a
   que alguien se acuerde de reiniciarlo: recibe el `REVOKED` firmado, se apaga, y
   al arrancar `fetchSecrets` recibe «unauthorized: revoked», que no se arregla
   reintentando. Antes, revocar no le quitaba nada a un proceso ya corriendo.

Defensas, porque una señal que provoca reinicios es un arma si se descuida: firma
de la maestra pineada, `ns` que coincida, frescura y anti-replay, **gracia de
arranque** y **piso entre avisos** (si la configuración nueva rompe el arranque, sin
eso el servicio entra en ciclo) y **jitter** (diez agentes del mismo `ns` no salen
todos en el mismo segundo).

```js
import { watchEnv } from '@dotrino/vault/env'
await watchEnv({ ns: 'miapp' })                       // termina el proceso al cambiar
await watchEnv({ ns: 'proxy', onUpdate: (i) => … })   // o decide tú (ver abajo)
```

`onUpdate` es para cuando terminar **no es una opción**. El caso real es el proxio:
reiniciarlo corta el transporte de todo el ecosistema, así que anota el aviso, lo
publica en su `GET /peers` y deja el momento a un humano.

### Precedencia: el vault MANDA

Los valores del vault **pisan** los del `.env` y los del entorno. El vault no
reemplaza al `.env` —que sigue siendo lo que arranca una máquina sin enrolar— pero
sí tiene la última palabra sobre las claves que administra.

Esa es la pieza que hace barata la **rotación**: cambias el valor en un solo lugar y
ningún `.env` viejo olvidado en un VPS puede seguir ganando. Con la precedencia al
revés (como estaba hasta la 0.14.0) rotar exigía además ir a limpiar cada copia
rancia —el trabajo que se quería evitar— y, peor, el servicio arrancaba con la llave
vieja **sin decir nada**.

Lo que sí se dice en voz alta: al arrancar se listan las claves que el vault tuvo que
pisar. Es la señal de que en esa máquina quedó un `.env` por limpiar.

```bash
DOTRINO_ENV_OVERRIDE=0 node server.js   # escotilla: por esta corrida, gana el entorno
dotrino-env check                        # dice qué claves pisaría en esta máquina
```

### API `@dotrino/vault/env`

- `loadEnv({ ns?, dir?, override?, wait?, required?, onRetry? }) → { ns, secrets, injected, overridden, skipped }`
  (por defecto **pisa** lo que ya esté en el entorno; `override: false` invierte la regla).
  `overridden` son las claves que tenían otro valor y el vault reemplazó.
- `applyEnv(secrets, override?) → { injected, overridden, skipped }` — vuelca un bundle
  ya obtenido, sin pedirlo. Para servicios que **no pueden bloquear su arranque**
  esperando al vault y lo aplican cuando llega (el caso del proxy: el vault le habla
  *por* el proxy, así que esperarlo sería un abrazo mortal).
- `serviceDir(ns)`, `serviceRoot()`, `listEnrolled()`, `resolveNs(ns?)`
- Entorno: `DOTRINO_NS` · `DOTRINO_ENV_DIR` · `DOTRINO_ENV_HOME` · `DOTRINO_ENV_QUIET` ·
  `DOTRINO_ENV_OVERRIDE`
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

- `startPairing({ scope?, ttlMs?, label?, mode?, account? }) → { qr, expiresInMs }`
- `stopPairing(token)`
- `listPending() → [{ deviceId, label }]`
- `approve(deviceId, code) → Promise<{ ok, deviceId }>`  (code = lo que muestra el dispositivo)
- `reject(deviceId)`
- `listMachines() → Promise<[{ sub, deviceId, label, scope, exp, nonce }]>`
- `revoke(nonce) → Promise`
- `getSelfCert() → Promise<cert>`  (self-cert `P ← P`, para actuar además de cliente)
- `onPendingChange(fn)`, `onAdopted(fn)`, `close()`

Cripto y firma: `@dotrino/identity`. Transporte: `@dotrino/proxy-client`. No reimplementa
nada del ecosistema.

### Qué atiende, y qué NO

Esta bóveda **no es** el daemon del PC: comparte el núcleo de enrolamiento
(`lib/src/enroll.js`, el mismo archivo), pero atiende menos mensajes del protocolo.

Atiende: `vault.hello` (la llave que pide el QR corto), `vault.enroll` +
`vault.acta.sealed` (enrolar y adoptar), `vault.renew` (**renovación automática** del
cert de una máquina vigente: sin esto toda máquina enrolada caducaba a los 30 días) y
`vault.devices` (lista + revocados, con re-emisión del `REVOKED` firmado).

**No** atiende, y hoy solo existen contra el daemon `dotrino-vault`:

| Falta | Qué implica |
|---|---|
| `vault.sign` | una máquina no puede pedirle a la maestra que firme por ella |
| `vault.store` / `vault.get` | no hay store centralizado, ni edición de perfil, ni clave de contenido |
| `vault.secrets` | `@dotrino/vault/config` (el reemplazo del `.env`) **no funciona** contra un dispositivo |
| `vault.admin` | sin consola remota |
| bitácora, cifrado en reposo, candado, multi-perfil | son del daemon; en el navegador dependen de `@dotrino/identity` |

MIT · parte de [Dotrino](https://dotrino.com).

## Agente SSH con llaves en memoria (`dotrino-env ssh-agent`)

La llave SSH es un secreto más del cajón (`SSH_KEY_*`, el archivo en base64). Al arrancar,
el agente pide el cajón a la bóveda (con la aprobación del teléfono si el aparato la pide),
carga las llaves en memoria y sirve el protocolo de `ssh-agent`; en el disco no queda nada.
`dotrino-env ssh-agent --ns ssh` imprime el `SSH_AUTH_SOCK`. Como librería:
`loadPrivateKey`, `publicLine`, `signSsh` (`src/sshKeys.js`) y `startSshAgent` (`src/sshAgent.js`).
