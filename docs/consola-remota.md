# Consola remota de la bóveda — plan de diseño

> Estado: **PROPUESTO**, sin implementar. Complementa `acta-de-perfil.md` (el modelo) y
> `pairing-protocol.md` (el emparejamiento endurecido). Si hay conflicto, mandan esos dos.

## 1. Qué se quiere

Una aplicación en un **dispositivo ya emparejado** que haga de frontend de la bóveda sin
estar frente al PC: ver quiénes son del perfil, **conectar un dispositivo nuevo**
(mostrar el QR y aprobarlo), **quitar** uno, revisar la bitácora y guardar **datos
sensibles** del usuario.

Hoy eso no existe. El daemon solo atiende, de un dispositivo enrolado, `sign`, `store`,
`get`, `devices`, `renew` y `secrets` (`src/vault.js:290-300`); `pair`, `approve`,
`reject`, `revoke` y `caps` viven únicamente en la CLI/TUI local, contra el socket del
daemon (`src/ctl.js`, `src/vaultControl.js`). La consola web de `vault.dotrino.com`
(`web/src/Console.vue`) sí gestiona el acta, pero hablándole al **iframe de identidad**
—«este dispositivo es bóveda»—, no al daemon del PC.

## 2. La decisión de fondo

El acta tiene una **lista cerrada** de capacidades (`sign`/`store`/`read`/`secrets`) y
dice, textual, que *admitir miembros no es una capacidad: es el rol de master, y lo tiene
exactamente un miembro*. Esta app obliga a abrir esa lista. Se abre **una sola rendija**,
y con esta división:

| Se delega (capacidad `admin`) | NO se delega (sigue siendo local, del master) |
|---|---|
| ver el acta y la bitácora | cambiar `caps` de un miembro |
| iniciar un emparejamiento (mostrar el QR) | traspasar el mando (`handover`) |
| **aprobar** / rechazar un emparejamiento | conceder o quitar `admin` |
| **revocar** un miembro | borrar un perfil · candado (`lock`/`unlock`) |
| — | secretos de servicio (`secret set/get/list`) |

La regla que ordena la tabla: **un admin puede admitir y expulsar, pero no puede
reescribir quién manda ni ascender a nadie.** Con eso, un teléfono robado y con `admin`
hace daño acotado y **reversible desde el PC** (se le revoca); sin esa frontera, podría
traspasarse el mando y dejarte fuera de tu propia cuenta, que es irreversible por diseño
(no hay recuperación ni frase de respaldo).

### Por qué aprobar de forma remota es aceptable

Porque el código de 6 dígitos es un **compromiso**, no un secreto que viaja: lo genera el
dispositivo nuevo, lo muestra en su pantalla, y la bóveda solo firma el cert si el código
tecleado recomputa el compromiso (`lib/src/enroll.js:290-348`). Aprobar exige, sí o sí,
haber leído la pantalla del aparato que entra. Mover ese tecleo del PC al teléfono no
debilita nada: cambia *dónde* está el humano, no *qué* tiene que demostrar.

Lo que **no** cierra —igual que hoy, residual A1/A2 de `pairing-protocol.md`— es que
alguien te **dicte** el código por otro canal. Contra eso: la copy de advertencia, que
reconozcas el `deviceId`, y el aviso a todos los dispositivos (§5).

## 3. F1 — La capacidad `admin` en el acta

- Scope del cert: **`vault:admin`**. Capacidad del acta: **`admin`**.
- `SCOPE_TO_CAP` en `lib/src/enroll.js:55` suma `'vault:admin': 'admin'`.
- **Reglas de forma** (validación del acta, en `@dotrino/identity/acta` — un acta que las
  incumpla **no valida**, como ya pasa con `secretos-sin-cn`):
  - `admin` solo en miembros con **`cn: null`**: un servicio nunca administra
    (`admin-con-cn`).
  - `admin` **no implica** `sign`/`store`/`read`; son ortogonales.
  - El **master siempre puede todo** sin llevar `admin` en la lista.
- **`admin` no se emparejaba: se concede.** No hay `dotrino-vault pair --admin`. Un
  dispositivo entra normal y después, **en el PC**, `dotrino-vault caps <ID> +admin`. Así
  el QR que circula nunca puede otorgar administración, y conceder es un gesto deliberado
  del dueño que queda escrito en el acta.
- La TUI y `dotrino-vault members` muestran `admin` con su etiqueta propia
  («Administra el perfil»), destacada: es la capacidad más fuerte que se delega.

## 4. F2 — Las operaciones remotas

Mensajes nuevos en `lib/src/protocol.js`, todos **dispositivo → bóveda** con
`{ data, signature, cert }`, verificados como los demás: `verifyChain` contra la maestra,
`expectedScope: 'vault:admin'`, revocación y ventana de frescura ±5 min.

| Mensaje | `data` | Qué hace |
|---|---|---|
| `vault.admin.pending` | `{ op, ts, nonce }` | devuelve `desk.listPending()` |
| `vault.admin.pair` | `{ op, scope?, label?, ts, nonce }` | `desk.startPairing()`; responde la **invitación ya codificada** (`lib/src/invite.js`) para que la app pinte el QR |
| `vault.admin.approve` | `{ op, code, deviceId, ts, nonce }` | `desk.approve(code, { deviceId })` |
| `vault.admin.reject` | `{ op, deviceId, ts, nonce }` | `desk.reject(deviceId)` |
| `vault.admin.revoke` | `{ op, nonce: certNonce, ts, nonce }` | `desk.revoke(certNonce)` |
| `vault.admin.audit` | `{ op, since?, ts, nonce }` | últimas N entradas de la bitácora |

Tres cosas que **no** son opcionales:

1. **`nonce` de un solo uso.** `sign`/`get` son idempotentes y les basta la ventana de ±5
   min; `approve` y `revoke` **cambian estado**, así que un replay dentro de la ventana
   importa. El daemon guarda los nonces vistos durante 10 min y rechaza el repetido
   (`replay`). Sin esto, la ventana anti-replay que ya existe no alcanza.
2. **El scope pedido en `pair` no puede incluir `vault:admin` ni `vault:secrets:*`.** Un
   admin no empareja servicios ni crea otros admins. Se rechaza en el propio handler, no
   solo en la UI.
3. **Auditar el actor.** Cada entrada de bitácora de una op remota lleva **qué
   dispositivo** la pidió (`by: <deviceId>`), no solo qué pasó. Hoy `audit('approve', …)`
   no distingue quién aprobó porque solo podía ser el PC.

Lo que **no** se expone, y conviene dejarlo escrito para que nadie lo agregue «por
simetría»: `caps`, `handover`, borrado de perfil, `lock`/`unlock` y **cualquier cosa de
`secrets.json`**. Ese archivo son tokens de producción cifrados en reposo con clave ligada
a la máquina (`src/secretsStore.js`): sacarlos hacia un navegador es mover el dominio de
confianza entero.

## 5. F3 — Avisar a todo el mundo (esto es parte del plan, no un extra)

Un enrolamiento o una revocación hechos a distancia son **invisibles** hoy. Se añade un
`vault.admin.event` que la bóveda **empuja por `sendByPubkey` a todos los miembros**
(cola offline 24 h) cuando se enrola, se revoca o cambian los `caps`, firmado por la
maestra: `{ body: { ev, deviceId, by, ts }, signature }`.

Es la contrapartida obligatoria de delegar la administración: si un admin comprometido
mete un aparato, tienes que verlo en el resto de tus dispositivos sin ir a mirar la
bitácora. Las apps que ya usan `@dotrino/notifications` lo muestran; la consola lo pinta
como aviso.

## 6. F4 — Datos sensibles del usuario

Van al **contenido del perfil** (`src/threadStore.js` + `src/store.js`), cifrados con la
CEK de la cuenta y accesibles con `vault:store` — el mismo camino que hilos y perfil.
Métodos nuevos: `secure.list` / `secure.put` / `secure.del` sobre un árbol propio.

**No se toca `secrets.json`**: ese es el cajón de los *servicios* (`proxy`, `geo`…),
acotado por CN, y no es el sitio de las contraseñas de una persona. Son dos cosas con el
mismo nombre coloquial y distinto dueño.

Nota de alcance: esto es el **almacén**. Una app de contraseñas con su UI, generador y
autocompletado es otra cosa y no entra aquí.

## 7. F5 — La aplicación

**Una vista más en `dotrino-vault/web`, no un repo nuevo.** `Console.vue` ya sabe pintar
el acta, leer QR con `jsqr` y generar QR con `qrSvg`; lo que cambia es **con quién habla**:
en vez de resolverlo todo contra el iframe de identidad, cuando el perfil vive en una
bóveda remota manda estos mensajes por el proxy. La app detecta el caso y adapta la
pantalla; el usuario ve la misma consola.

Cumple `CONVENCIONES-APPS.md` como cualquier app: `<dotrino-topbar>` con `profile`, PWA,
bilingüe es/en, GoatCounter, `<meta name="commit">`. La copy va en lenguaje llano (§9.1):
«Conectar un dispositivo», «Quitar», nunca «emitir un certificado de delegación».

Detalle de UI que decide la seguridad de todo lo anterior: la pantalla de aprobación
**pide teclear el código que muestra el otro aparato** y enseña el `deviceId` en grande.
Nunca un botón «Aprobar» a secas, y **jamás** un camino donde el código llegue solo.

## 8. Pruebas (`dotrino-test`, cada pieza en su caja)

- Protocolo: cada op de admin sin `vault:admin` → rechazada; con cert revocado →
  rechazada; replay del mismo `nonce` → rechazado; `pair` pidiendo `vault:admin` o
  `vault:secrets:*` → rechazado.
- Acta: `admin` con `cn` → no valida. Un admin intentando `caps`/`handover` → no hay
  camino (no existe el mensaje) y el acta que lo intentara no sella.
- E2E en contenedores: bóveda + dispositivo-admin + dispositivo-nuevo; el admin empareja y
  aprueba al nuevo **sin tocar el PC**, y el aviso llega a los tres.
- Navegador con Playwright: la consola remota, el QR y la pantalla de código.

## 9. Orden de trabajo

1. F1 (capacidad `admin` + reglas de forma + `caps +admin` en la CLI) — sin esto no hay nada.
2. F2 (mensajes y handlers, con nonce anti-replay y auditoría del actor).
3. F3 (avisos) — **antes** de exponer la app, no después.
4. F5 (UI) contra F2.
5. F4 (datos sensibles), independiente del resto; se puede adelantar o diferir.

## 10. Residuales aceptados

- Un dispositivo con `admin` **robado y desbloqueado** puede meter aparatos hasta que lo
  revoques. Acotado (no toca el mando) y reversible; el aviso de F3 es lo que lo hace
  detectable. Es el precio explícito de no tener que ir al PC.
- El phishing por **dictado del código** sigue abierto, igual que hoy.
- La bóveda sigue sin recuperación: perder la llave que sella es perder la cuenta.
