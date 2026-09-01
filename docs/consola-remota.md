# Consola remota de la bóveda — plan de diseño

> Estado: **COMPLETA** — F1–F5 implementadas y probadas de punta a punta en contenedores
> (`dotrino-test`, `npm run smoke:consola`). Complementa `acta-de-perfil.md` (el modelo) y
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
| **variables de entorno**: crearlas, darles valor, y ver el valor de las **públicas** | **el valor de una variable privada** · **borrar** variables |

La regla que ordena la tabla: **un admin puede admitir y expulsar, pero no puede
reescribir quién manda ni ascender a nadie.**

### Las variables de entorno, y por qué esta fila existe (2026-08-12)

La versión original de este documento decía que **nada** de `secrets.json` cruzaba, y lo
razonaba así: *«sacarlos hacia un navegador es mover el dominio de confianza entero»*. La
objeción sigue siendo correcta —por eso la respuesta no fue abrir el archivo, sino
**partir las variables en dos**:

| | **Pública** | **Privada** (lo que se nace) |
|---|---|---|
| La lee el servicio dueño | sí | sí |
| Su VALOR sale de la máquina de la bóveda | sí, hacia la consola | **nunca** |
| Se le puede poner un valor nuevo desde la consola | sí | sí, **a ciegas** |
| Se puede cambiar a la otra columna | sí, a privada (sin tocar el valor) | **nunca** (`PRIVATE_STAYS_PRIVATE`): se borra y se crea otra |

Lo que cruza, entonces, no es «los secretos»: es lo que su dueño **marcó** como mostrable,
una variable a la vez y con la marca puesta a mano en la máquina de la bóveda (o al
crearla desde la consola). El resto se puede **rotar sin verse**, que es justo lo que hace
falta cuando estás lejos y hay que cambiar una llave.

Tres cosas sostienen la fila:

1. **Se nace privada.** Actualizar el binario no vuelve visible nada de lo que ya había
   (`secretsStore.js`, migración v2→v3), y rotar un valor **conserva** la visibilidad: si
   no, exponer un secreto sería un descuido de un `set` en vez de una decisión.
2. **Lo que sale, sale cifrado.** La lista entera —valores, nombres y qué servicios corres—
   viaja sellada con la clave de contenido del perfil, la misma del `store`: el proxy
   transporta y no ve nada. Y el valor que se manda a guardar viaja igual; un `var.set`
   con el valor en claro se **rechaza**, no se «arregla».
3. **Privada es para siempre (2026-08-22).** Una pública se puede tapar; una privada no se
   destapa, ni desde la consola ni con `secret visibility … public` en la máquina de la
   bóveda, ni de refilón con `set --public` sobre la misma clave. En la consola la casilla
   «Privada» de una variable que ya lo es va **deshabilitada**. Si hace falta ese valor a
   la vista, se borra la variable y se crea otra pública — un gesto que queda a la vista.
4. **Borrar no se delega.** Un aparato robado con `admin` puede escribir configuración
   —daño acotado y reversible, se le revoca— pero no puede dejar a tus servicios sin
   ninguna. Escribir, además, **avisa a todos los miembros** (§5).

Y una regla de pantalla que sale de todo esto: **la consola guarda con UN solo botón**.
Cada guardado hace que la bóveda avise al servicio y el servicio **salga** para releer su
configuración entera (`watchEnv`); con un «Guardar» por fila, cargar seis variables eran
seis reinicios, y los cinco primeros arrancaban el servicio a medio configurar. Por eso se
edita todo lo que haga falta —incluido pegar un `.env` entero **en el campo del nombre**,
que se reparte en filas— y se confirma una vez, en un `var.setMany`.

Y de ahí sale la segunda regla de esa pantalla: **añadir varias no es una pantalla aparte,
ni un botón**. Hay siempre una fila en blanco al final y, en cuanto empiezas a llenarla,
nace otra debajo; cargar seis variables es teclear seis veces. Antes había un botón
«Agregar variable» y, al lado, un cuadro de texto suelto con su propio botón de repartir:
tres controles para lo que ahora hacen la propia fila y el pegado.

El riesgo que sí se acepta, dicho en voz alta: un admin comprometido puede **envenenar**
la configuración de un servicio (apuntar una URL a otro sitio, meter una llave inservible).
Se detecta por el aviso firmado y por la bitácora —cada `var.set` queda con el aparato que
lo pidió—, y se corta revocando ese aparato. Con eso, un teléfono robado y con `admin`
hace daño acotado y **reversible desde el PC** (se le revoca); sin esa frontera, podría
traspasarse el mando y dejarte fuera de tu propia cuenta, que es irreversible por diseño
(no hay recuperación ni frase de respaldo).

### ⛔ AGREGAR APARATOS DESDE AQUÍ: QUITADO (dueño, 2026-08-31)

`pending`, `pair`, `approve` y `reject` **ya no existen** — ni la operación, ni el mensaje,
ni el botón. No están escondidos: quitados.

**Por qué.** Existían para ahorrarse ir hasta la máquina de la bóveda. El **multivault**
quita esa fricción de raíz: cualquier otra selladora abierta —el teléfono, un segundo PC—
admite el aparato, y lo hace firmando de verdad, no pidiéndoselo a otro. Así que esto dejó
de comprar nada y seguía pidiendo lo caro.

**Lo caro.** Admitir a alguien es **emitir un certificado Y sellar el acta**, y las dos son
de la maestra. La regla del acta dice que la maestra solo sella el acta y reenvuelve sobres,
y que **con la bóveda cerrada no firma nada**. Una consola que admite aparatos obliga a
tener la maestra disponible a distancia, que es exactamente lo que el candado impide.

Se estudió una variante —dejar sellar al admin *solo si el acta únicamente agrega un
aparato*— y se descartó: un miembro trae `caps`, así que «solo agrega un aparato» incluye
«agrega otra selladora» salvo que se acoten; y aun acotándolos, convierte una regla de una
línea (`canSeal(anterior, sealedBy)`) en una regla de **diff** que tendrían que implementar
igual el proxio, cada aparato y el registro de selladores. Cada implementación distinta es
una toma de cuenta.

**Lo que queda a distancia:** mirar el acta y la bitácora, **quitar** un aparato y las
variables de entorno.

### Por qué aprobar de forma remota era aceptable (histórico)

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
  - `admin` solo en miembros con **`cn: null`**: un servicio nunca administra. No hace
    falta una regla nueva — al no estar en `SERVICE_CAPS`, un acta que se la dé a un
    miembro con CN falla con el `servicio-con-capacidades-de-dispositivo` de siempre.
  - `admin` **no implica** `sign`/`store`/`read`; son ortogonales.
  - El **master siempre puede todo** sin llevar `admin` en la lista.
- `PAIRED_CAPS` (nuevo) es lo que recibe un recién emparejado: `sign`/`store`/`read`, sin
  `admin`. La génesis nace con eso mismo.
- **`admin` no se emparejaba: se concede.** No hay `dotrino-vault pair --admin`. Un
  dispositivo entra normal y después, **en el PC**, `dotrino-vault caps <ID> +admin`. Así
  el QR que circula nunca puede otorgar administración, y conceder es un gesto deliberado
  del dueño que queda escrito en el acta.
- La TUI y `dotrino-vault members` muestran `admin` con su etiqueta propia
  («Administra el perfil»), destacada: es la capacidad más fuerte que se delega.

## 4. F2 — Las operaciones remotas

**UN** mensaje `vault.admin` con `data.op`, no seis: la regla vive en un solo sitio
(`lib/src/admin.js`, módulo puro como `enroll.js`) y por lo tanto se comprueba una sola
vez. Va **dispositivo → bóveda** con `{ data, signature, cert }`, verificado como los
demás: `verifyChain` contra la maestra, `expectedScope: 'vault:admin'`, revocación y
ventana de frescura ±5 min. Responde `vault.admin.result`.

| `data.op` | Campos | Qué hace |
|---|---|---|
| `status` | `{ ts, nonce }` | `{ locked }` — el candado del perfil, para que la consola pueda explicarse |
| `revoke` | `{ certNonce \| sub, ts, nonce }` | retira un papel, o QUITA el aparato entero por su llave |
| `audit` | `{ limit?, ts, nonce }` | últimas N entradas de la bitácora (tope 500) |
| `vars` | `{ ts, nonce }` | los dos cajones de variables **sellados**: nombres y visibilidad de todas, y el **valor solo de las públicas** |
| `var.set` | `{ ns \| pub, key, enc, public?, ts, nonce }` | crea o cambia una variable. `enc` es el valor **sellado** con la clave de contenido del perfil; sin él se rechaza. Exactamente un destino: un scope (`ns`) o un aparato (`pub`) |
| `var.setMany` | `{ ns \| pub, enc, public?, ts, nonce }` | **varias de una vez**: `enc` sella `{ items: [{ key, value, public? }] }` —los nombres también van dentro—. Mismo permiso y misma frontera que `var.set` (borrar sigue sin delegarse); lo que cambia es que la bóveda las guarda juntas y manda **un solo aviso de cambio**, o sea que el servicio se reinicia una vez con la configuración entera en vez de una vez por variable |

Cuatro cosas que **no** son opcionales:

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
4. **Con el perfil CERRADO no se administra** (2026-08-31). El candado es de la consola
   —los aparatos ya emparejados siguen leyendo, guardando y firmando con su llave—, así
   que cerrar el perfil tiene que cerrar **esto**, que es la consola. Se atienden solo las
   de mirar (`ADMIN_OPS_WHILE_LOCKED`: `pending`, `audit`, `vars`) y el resto responde con
   el **código** `vault-locked`; `pending` devuelve además `locked`, que es lo que la
   consola ya sondea, para poder apagar los botones y decir por qué en vez de dejar que se
   pulsen para recibir un error.

   **Qué faltaba, dicho en voz alta:** `pair` y `approve` pasaban con el perfil cerrado, y
   `approve` firma un **certificado de 30 días con la maestra**. O sea que el candado
   frenaba `dotrino-vault pair` **en la máquina** (`src/daemon.js`) y no frenaba lo mismo
   **por la red**, que es el camino que importa. El rechazo va después de autorizar (a un
   desconocido no se le cuenta el estado del perfil) y **antes** de quemar el nonce: quien
   reintente tras abrir la bóveda no tiene por qué inventarse otro.

Lo que **no** se expone, y conviene dejarlo escrito para que nadie lo agregue «por
simetría»: `caps`, `handover`, borrado de perfil, `lock`/`unlock`, **el valor de una
variable privada** y **borrar** variables. `secrets.json` son tokens de producción cifrados
en reposo con clave ligada a la máquina (`src/secretsStore.js`); lo único que sale de ahí
es el valor de las marcadas como públicas, y sellado (§2).

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

Van al **contenido del perfil** (`src/threadStore.js`), cifrados con la CEK de la cuenta
y accesibles con `vault:store` — el mismo camino que hilos y perfil. Métodos:
`secure.list` / `secure.get` / `secure.put` / `secure.del` sobre un árbol propio
(`data.secure` en `threads.json`).

**Dos sobres cerrados por ficha, y la bóveda no abre ninguno.** Cada ficha guarda `meta`
(lo justo para pintar la lista: nombre, tipo, carpeta) y `enc` (el valor). Los sella el
dispositivo con `identity.sealContent`; aquí solo se comprueba que sean cadenas y que no
pasen de 64 KB — nunca qué dicen. Que sean **dos** y no uno es lo que permite listar sin
bajar todas las contraseñas de golpe, y que el nombre («Banco») tampoco quede legible en
la bóveda. Tope de 2000 fichas: un dispositivo con `vault:store` no llena el disco.

`secure.get` no estaba en el plan original, pero sin él listar tendría que devolver los
valores, que es justo lo que se quiere evitar.

**Leer datos sensibles exige `vault:store`, no `vault:read`.** Aunque `list`/`get` sean
lecturas, quedan **fuera** de `STORE_READ_METHODS`: a un dispositivo al que solo le diste
«leer» no se le abren las contraseñas.

**No se toca `secrets.json`**: ese es el cajón de los *servicios* (`proxy`, `geo`…),
acotado por CN, y no es el sitio de las contraseñas de una persona. Son dos cosas con el
mismo nombre coloquial y distinto dueño.

Nota de alcance: esto es el **almacén**. Una app de contraseñas con su UI, generador y
autocompletado es otra cosa y no entra aquí.

## 7. F5 — La aplicación

**La misma página de siempre, en `vault.dotrino.com/vault`** (ruta única desde
2026-08-26; las de las dos etapas anteriores, `/devices` y `/dispositivos`, se retiraron
a mano del dueño y ya no existen — lo que sigue entrando por donde sea es la invitación,
que viaja en el #fragment y no mira la ruta). En el menú se llama **«Mi bóveda»**. No hay app nueva ni subdominio nuevo: quien administra ya tiene la identidad en
ese aparato, y el cert **es** la credencial — no hay login ni contraseña.

**Y la página decide sola con quién habla.** Al abrirla mira el certificado de delegación
de este aparato: si lo hay, la bóveda es otra máquina y se conecta a ella (esto); si no lo
hay, la bóveda es este mismo aparato y lo que hace es **encender su mostrador** y quedarse
escuchando a los demás. Era una casilla que había que encontrar y marcar.

La sección de administración **solo aparece si `canAdminVault()`**, que mira el scope del
cert. Y eso es únicamente para saber qué pintar: la bóveda vuelve a comprobarlo en cada
petición, porque una pantalla no es un control de seguridad.

**Una vista más en `dotrino-vault/web`, no un repo nuevo.** `Console.vue` ya sabe pintar
el acta, leer QR con `jsqr` y generar QR con `qrSvg`; lo que cambia es **con quién habla**:
en vez de resolverlo todo contra el iframe de identidad, cuando el perfil vive en una
bóveda remota manda estos mensajes por el proxy. La app detecta el caso y adapta la
pantalla; el usuario ve la misma consola.

Cumple `CONVENCIONES-APPS.md` como cualquier app: `<dotrino-topbar>` con `profile`, PWA,
bilingüe es/en, GoatCounter, `<meta name="commit">`. La copy va en lenguaje llano (§9.1):
«Conectar un dispositivo», «Quitar», nunca «emitir un certificado de delegación».

**Dónde se administra cada variable (2026-08-13).** No hay un formulario único con un
desplegable de destino: se escribe **donde se ve de quién es**. Las de un servicio, en la
**fila de ese servicio** de la lista de dispositivos, debajo de sus permisos; las de un
grupo, **dentro del apartado de su grupo**, que se crea primero y se llena después. El
componente es el mismo en los dos sitios (`web/src/Vars.vue`). La casilla dice **«Privada»**
—que es como nacen— en vez de describir la consecuencia («que su valor se pueda ver desde
aquí»), y un grupo recién creado vive solo en la pantalla hasta su primera variable, porque
en la bóveda un cajón vacío se borra solo.

**Donde no se puede, no sale nada.** El apartado «Sus variables» aparece en la fila de un
**servicio** y en ninguna otra: solo él las lee (`requireService`), así que en un teléfono no
hay ni formulario ni un letrero explicando por qué no lo hay — un «aquí no» repetido en cada
fila de la lista es ruido, y la §5.1 lo saca de una pantalla administrativa. Lo mismo en la
TUI: la barra de teclas ofrece `e variables` solo si el aparato señalado es un servicio (ya
era la regla de esa barra: anunciar teclas muertas confunde). Lo que un aparato arrastre de
antes se sigue viendo y se puede cambiar — configuración invisible es configuración que nadie
arregla el día que falla.

Detalle de UI que decide la seguridad de todo lo anterior: la pantalla de aprobación
**pide teclear el código que muestra el otro aparato** y enseña el `deviceId` en grande.
Nunca un botón «Aprobar» a secas, y **jamás** un camino donde el código llegue solo.

## 8. Pruebas (`dotrino-test`, cada pieza en su caja)

- Protocolo: cada op de admin sin `vault:admin` → rechazada; con cert revocado →
  rechazada; replay del mismo `nonce` → rechazado; `pair` pidiendo `vault:admin` o
  `vault:secrets:*` → rechazado.
- Acta: `admin` con `cn` → no valida. Un admin intentando `caps`/`handover` → no hay
  camino (no existe el mensaje) y el acta que lo intentara no sella.
- Datos sensibles (`test/secure-store.test.mjs`): listar no baja los valores; en el disco
  no se ve ni el valor ni el nombre; editar conserva id y fecha de creación; topes de
  tamaño y de número de fichas; `list`/`get` fuera del set de solo-lectura.
- E2E en contenedores (`dotrino-test`, `npm run smoke:consola`): bóveda + dispositivo-admin
  + dispositivo-nuevo, cada uno en su caja, con la bóveda corriendo **como binario** y
  manejada con su CLI real. El admin empareja y aprueba al nuevo **sin tocar el PC**, y el
  aviso firmado llega a los demás. Cubre también: sin `admin` no se administra, conceder
  `+administra` llega al cert al renovar, `pair` con scope prohibido, quitar `-administra`
  corta en el acto, y F4 por el camino real.

  **Ya sirvió, y de sobra.** Destapó que esto no funcionaba en absoluto (§11).
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

## 11. Lo que destapó el E2E (y no era poco)

Con F1–F5 «implementadas» y 141 pruebas verdes, **la consola remota no funcionaba**. Nada
de esto se veía sin levantar las tres máquinas de verdad; son tres fallos distintos que se
tapaban entre sí.

1. **El vault dependía de un `@dotrino/identity` anterior a la capacidad `admin`**
   (`0.37.1`, mientras el pilar ya iba por `0.38.0`). `cleanCaps` filtra contra `CAPS`, así
   que el acta **descartaba `admin` en silencio**: `caps <ID> +administra` decía «Listo» y
   no cambiaba nada. Un pilar publicado no sirve de nada si quien lo consume no lo sube.
2. **El scope del cert se copiaba del cert viejo al renovar.** Como la autorización mira el
   **cert**, no el acta, un permiso concedido después del emparejamiento **no llegaba
   nunca** — y uno retirado seguía valiendo hasta que el cert caducara, **hasta 30 días**.
   Arreglado: el scope del cert nuevo sale de `Acta.memberScopes`, y si el miembro ya no
   está en el acta, no se renueva.
3. **Las operaciones de admin no cruzaban con el acta.** Los secretos ya lo hacían (con su
   CN), pero `vault.admin` se conformaba con el cert. Ahora es **cert ∩ acta**, que es lo
   que el propio `memberCan` decía que debía ser, y por eso quitar `administra` corta en el
   acto en vez de esperar a la caducidad.

De regalo, dos cosas menores: `handleStore` aceptaba como método cualquier miembro heredado
de `Object` (`method: 'toString'` pasaba el filtro), y el aviso a los miembros se mandaba
**una vez por delegación** en vez de una por llave, así que un aparato veterano recibía el
mismo aviso repetido, una vez por renovación acumulada.

**La lección, para la próxima pieza:** «implementado y con tests verdes» no es «funciona».
Lo que faltaba era el escenario donde las piezas se hablan entre máquinas, que es el único
sitio donde estos tres fallos existen.
