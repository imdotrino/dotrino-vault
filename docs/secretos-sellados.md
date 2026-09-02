# Secretos sellados por destinatario

> Diseño acordado el 2026-08-17, **implementado y publicado el 2026-08-18**
> (`@dotrino/identity@0.53.0`, `@dotrino/vault@0.25.0`). Nace de una pregunta
> concreta: el vault corre en un VPS alquilado, y el dueño de esa máquina puede
> leer el disco. ¿Qué se hace al respecto?
>
> **DESPLEGADO Y MIGRADO en producción el 2026-08-18.** El vault del VPS corre
> `dotrino-vault 0.39.1` y su `secrets.json` está en v4 (sellado). Los dos proxios
> registraron su llave de cifrado **sin re-enrolarse** y conservan su `nodeId`. Ver §6
> para lo que se hizo y cómo volver atrás.

## 1. El problema, acotado

Lo que hay que proteger no es «el home del VPS»: son las **variables privadas**
de los servicios (`vault:secrets:<ns>`) — tokens de producción, credenciales de
TURN, configuración de federación de los proxios.

Hoy esos valores están sellados **en los dos tramos** del camino y en claro **en
el medio**:

| Tramo | Qué pasa | Dónde |
|---|---|---|
| Consola → vault | sellado con la **llave de contenido del perfil**, que el vault tiene: la abre con `identity.openContent` y guarda el texto en claro | `vault.js:594` (`var.set`), `lib/src/admin.js:198` |
| En reposo | cifrado con la clave **ligada a la máquina** (`/etc/machine-id` + `atrest.salt`, ambos en el mismo disco) | `lib/src/atrest.js` |
| Vault → servicio | sellado a la ECDH **efímera** (`ek`) del que pide, cuerpo firmado por la maestra | `vault.js:385` (`handleSecrets`) |

El proxy no ve nada en ningún momento — eso ya está bien resuelto. El que lo ve
todo es **el vault**, y por lo tanto quien controle esa máquina.

Y el cifrado en reposo no ayuda contra él: `machine-id` y `atrest.salt` viven en
el mismo disco que los datos. Una **instantánea del disco** los lleva los tres.
El propio `atrest.js` lo dice en su cabecera sin adornos — protege contra copiar
*un archivo*, no contra tener *la máquina*.

### Por qué importa más de lo que parece

El vault corre en su **propio VPS** (`74.208.234.139`), separado de los servicios
(proxy/signer/tunnel en `.192.49`, geo/results/reputation en `.11.221`). Es decir:
esa máquina sola concentra, en forma legible, los secretos de **todos** los
namespaces. Sellar por destinatario reparte el daño por máquina en vez de
concentrarlo — cada servidor solo puede comprometer lo suyo.

## 2. El diseño

Dos cambios que se sostienen mutuamente.

### 2.1. Los sobres se sellan al DESTINATARIO, no al perfil

Cada variable privada se guarda cifrada a la llave del **aparato que la va a
consumir**. El vault pasa a ser un **cartero**: reparte sobres que no puede abrir.

Faltaba una pieza: **el aparato no tenía una llave ECDH duradera**. Su llave de
dispositivo es ECDSA, solo firma — por eso `sealed.js` inventa una efímera en cada
petición. Ahora el servicio genera un par ECDH al enrolarse (`makeDeviceEncKey`), su
pública viaja en el enrolamiento y queda en el acta como `encPub` del miembro.

Toda la criptografía se reusó de `@dotrino/identity/content`, que ya la tenía
escrita y probada para el contenido del usuario: `makeContentKey`, `wrapForMember`
(ECDH **efímero**, quien abre solo necesita su privada), `openWrap`,
`encryptWithCek` y `makeGeneration` — que además devuelve `sinLlave`, los miembros a
los que no se les pudo envolver nada. **No se escribió criptografía nueva**; lo único
añadido fue `decryptWithCek`, el inverso que faltaba.

El cajón `dev` ya se indexaba por la `pub` del miembro (`secretsStore.js`), así que
ahí el destinatario ya estaba identificado.

**Repartir la llave no es opcional, y es el error que más caro salió.** Sellar sin
envolver deja al servicio recibiendo sobres que no puede abrir: `waitForSecrets`
reintenta **para siempre, en silencio**. Por eso se re-envuelve tras cada escritura y
al aprobar un servicio nuevo (`spreadKey`), y por eso un miembro sin llave sale en el
log en vez de perderse.

**Las públicas se quedan en claro a propósito.** La distinción `{ v, pub }` que ya
existe se vuelve literal: lo marcado como público sigue siendo legible —para eso
se marcó—, lo privado se vuelve opaco **hasta para el propio vault**. Y se sigue
naciendo privado.

### 2.2. La copia maestra vive bajo la contraseña del perfil

Un cartero que no puede abrir nada tampoco puede **fabricar sobres nuevos**, y
hacen falta: cada aparato que se enrola a un `ns` existente necesita su copia de
lo que ya había.

La salida es guardar, además de los sobres, una **copia maestra** de las privadas
cifrada con la **contraseña del perfil** — que no está en el disco. Queda:

| | Necesita contraseña | Por qué |
|---|---|---|
| **Servir** un bundle a un servicio | **no** | los sobres ya están sellados a sus destinatarios; se reenvían tal cual |
| **Enrolar** un aparato nuevo a un ns | sí | hay que re-sellar lo existente para él |
| **Poner o rotar** una variable | sí | hay que sellarla a los destinatarios actuales |

Esto **preserva** la propiedad que hoy hace que el candado sea usable: *perfil
bloqueado ≠ bóveda apagada*, los agentes siguen recibiendo lo suyo. Lo único que
se bloquea es administrar, que es lo que el candado ya significa hoy
(`vault.js:192`, `PROFILE_EDIT_METHODS`).

En el store son dos cosas distintas — `schemaVersion` 4, como quedó:

```
secrets.json
  ns:  { <ns>:  { vars: { KEY: { pub:false, owner:'ns:<ns>', e:{iv,ct} } | { pub:true, v:'…' } },
                  keyring: [{ gen, createdAt, wraps: { <memberPub>: {epk,iv,ct} } }] } }
  dev: { <pub>: { vars: {…}, keyring: [… una sola envoltura …] } }
  master: { v:1, iv, ct, tag }   ← las CEK, cifradas con la contraseña. Solo para administrar.
```

La CEK **nunca** se envuelve a la llave de esta bóveda: sería devolverle la capacidad
de leerlo todo, que es justo lo que el diseño quita. Hay un test que lo afirma.

### 2.3. Cómo se desbloquea

Desde la **consola de administración**, al enrolar: se pide la contraseña, viaja
**dentro del sobre firmado** (nunca en claro por el proxy, con el anti-replay que
ya hay), el vault deriva la llave, re-sella, y **la borra**.

- Es **por operación**, no una sesión. El candado (`unlocked`, en `profiles.js`) es
  otra cosa: dura hasta que alguien llame a `lock`, **hasta que pasen 5 minutos sin
  usarse** (bloqueo automático, `AUTO_LOCK_MS`) o hasta que se reinicie el servicio. Eso
  vale para la puerta de administración, pero la **llave derivada** no puede quedarse
  ahí — si se queda en RAM indefinidamente, todo este diseño no sirve para nada. Por eso
  se deriva, se usa y se pisa con ceros (`wipe` en `daemon.js`) en la misma operación.
- **Si el perfil no tiene contraseña, se hace directo.** Es el default correcto y
  no rompe a nadie, pero la consola tiene que **decir** que en ese perfil las
  privadas se leen desde una copia del disco. Prometer una protección que no está
  puesta es peor que no tenerla (ver §4.1).

## 3. Qué protege y qué no

Sin adornos, que es como está escrito el resto de este repo:

| | Instantánea del disco | RAM del VPS | Enrolar exige |
|---|---|---|---|
| **Hoy** | **lo lee todo** | expuesto siempre | nada |
| **Este diseño** | inútil | solo durante el desbloqueo | la contraseña |
| **Claro solo en la consola** | inútil | **nunca** | la máquina del dueño encendida |

Tres límites que hay que tener presentes:

1. **Al desbloquear se escribe la contraseña en la máquina que no se controla.**
   Desde ese momento, un binario del vault alterado puede guardársela y descifrar
   cuando quiera, en silencio. Esto defiende contra lo **pasivo** —instantáneas,
   discos dados de baja, el panel comprometido, una mirada a la RAM— no contra un
   vault modificado. La tercera fila de la tabla es la única donde esa capacidad
   nunca llega a existir en esa máquina.
2. **La máquina del servicio sigue teniendo su claro en RAM**: lo tiene que usar.
   El premio no es que desaparezca, es que cada máquina solo pueda comprometer lo
   suyo.
3. **No sustituye a sacar la maestra de esa máquina.** Con la maestra, quien
   controle el VPS puede suplantar al vault frente a la consola y conseguir que se
   le selle a una llave suya. El sellado cierra el disco y la RAM, no esa puerta.

## 4. Hallazgos que salieron al revisar el código

Los tres siguen siendo ciertos. **El primero está corregido**; los otros dos NO, y
son la razón por la que la contraseña tiene que ser una frase larga (§4.3).

### 4.1. `atrest.js` promete una protección que no existe

Su cabecera dice que la clave de reposo mezcla «la contraseña del perfil, si la
hay». **Ningún llamante la pasa**: los cinco —`src/store.js:33`,
`src/secretsStore.js:63`, `src/vault.js:52`, `src/threadStore.js:30`,
`lib/src/service.js:185`— invocan `atRestFor(dir)` a secas. Y no podría ser de otro
modo hoy sin romper que los agentes reciban secretos con el perfil bloqueado.

**Corregido** (commit `164ce99`): el comentario ya no promete lo que no hace, y
explica además por qué no puede hacerlo — el candado es de la consola, y un perfil
bloqueado tiene que seguir sirviendo a sus agentes.

Lo que sí se hizo en su lugar: la copia maestra (§2.2) es un cajón APARTE que solo
se necesita al administrar, que es exactamente la forma que el comentario describía
mal.

### 4.2. `profiles.json` se guarda EN CLARO, con el verificador dentro

`profiles.js:64,66` usa `readJson(file, null)` / `writeJson(file, data)` **sin
códec de reposo** — la única excepción del directorio. Y dentro va
`pwd: { salt, iter, verifier }`.

Con la contraseña en su papel actual (cerrar la administración de una máquina
propia) da igual. En cuanto pase a ser **material de llave**, ese verificador es el
camino corto: una instantánea del disco lo entrega, y desde ahí se ataca la
contraseña **fuera de línea** a 300.000 iteraciones de PBKDF2-SHA256 por intento.
El contador de intentos con espera exponencial (`profiles.js:212`) no interviene:
solo frena a quien pregunta por la red.

**PENDIENTE.** Lo que se hizo a medias: la copia maestra **no lleva verificador
propio** — su prueba es el tag AES-GCM (`sealer.js`, `openMaster`), así que atacarla
obliga a pasar por scrypt (`N=16384`, ~16 MB, duro con memoria). Pero el verificador
del CANDADO sigue en `profiles.json` en claro, y con él se ataca la misma contraseña
por el camino barato (PBKDF2-SHA256, que una GPU come rápido).

Queda por hacer: cifrar `profiles.json` en reposo, y separar el verificador del
candado de la llave que abre la copia maestra (hoy son la misma contraseña, así que
el eslabón débil manda).

### 4.3. El mínimo de contraseña son 4 caracteres

`profiles.js:239`. Razonable para un tope de velocidad; nada contra alguien con el
disco y una GPU.

**PENDIENTE, y es el que más importa de los tres.** Con §4.2 sin cerrar, la
contraseña es el eslabón único: cuatro dígitos son 10.000 combinaciones y caen en
minutos, y entonces todo lo demás de este documento no sirve de nada. **El cifrado no
vale más que la frase que lo abre.**

Mientras el mínimo siga en 4, la regla es operativa y no la impone el código: la
contraseña del vault de producción tiene que ser **cinco palabras al azar** (~71
bits), elegidas por una máquina y no por una persona — una frase hecha (`"vete de una
vez"`) tiene la entropía de un modismo, no la de su longitud.

## 5. Qué se tocó

- **`@dotrino/identity@0.53.0`** — `makeDeviceEncKey`/`importDeviceEncKey`,
  validación de forma de `encPub` en `checkShape`, la operación **`encpub`** para
  registrar la llave de un miembro ya admitido, `profileMembers` proyectando
  `encPub`/`canSeal`, y `decryptWithCek`.
- **`@dotrino/vault@0.25.0`** (`lib/`) — el agente genera su par ECDH al enrolarse
  (`service-identity` v2) y abre los sobres con él. **La llave de FIRMA no se toca**:
  de ella sale el `nodeId` del proxio.
- `src/sealer.js` (nuevo) — lo único que toca criptografía. El store recibe el puerto
  inyectado y no sabe cifrar, así que se prueba con un sellador falso.
- `src/secretsStore.js` — v4, migración verificando antes de reemplazar.
- `src/vault.js` — sella al escribir, reparte la llave, rota al expulsar, avisa si el
  perfil no tiene contraseña.

**El protocolo de red NO cambió**, y por eso `dotrino-proxy` no cambió una línea de
código: `fetchSecrets` sigue devolviendo el mismo objeto plano. Tampoco hubo que
re-vendorizar `dotrino-identity/vault/vendor/vault/` — `enroll.js` ya transportaba
`encPub` y `protocol.js` no se tocó.

### Dos capas de sobre, y hacen cosas distintas

Se quedan las dos, y conviene no confundirlas:

| Capa | Qué tapa | Contra quién |
|---|---|---|
| `ek` efímera por petición | el **tramo** — ni los nombres de tus variables | el proxio |
| sobre sellado al destinatario | el **reposo** — la bóveda reparte sin poder abrir | quien tenga el disco del VPS |

## 6. El despliegue, tal como se hizo

Hecho el 2026-08-18 en `74.208.234.139` (vault), `74.208.192.49` (proxy1) y
`74.208.11.221` (proxy2). Estos fueron los pasos, y sirven de guion si hay que
repetirlo en otra máquina:

1. **Poner una contraseña de verdad** al perfil (§4.3). Es lo primero porque la
   migración sella con la llave derivada de ella: cambiarla después obliga a
   re-sellar todo.
2. Desplegar el daemon y reiniciar. Comprobar que los dos nodos siguen recibiendo su
   configuración — hasta aquí no se ha tocado ningún dato y se deshace con un
   reinicio.
3. En cada nodo del proxio: subir a `@dotrino/vault@0.25.0` y **registrar su llave de
   cifrado** con la op `encpub`. **NO re-enrolar**: re-enrolar le cambia el `nodeId`
   y le vacía su cajón `dev` (`PROXY_PEERS`, `PROXY_PUBLIC_URL`), que va indexado por
   su llave — la federación se apaga en silencio y no se nota hasta el siguiente
   reinicio.
4. Comprobar en el vault que **los dos** miembros del ns `proxy` tienen llave de
   cifrado. Sin eso, el paso siguiente los deja sin configuración.
5. Desbloquear el perfil → corre la migración v3→v4. Comprobar que `secrets.json` no
   contiene ninguna cadena privada legible y que existe `secrets.json.v3.bak`. **Este
   es el punto de no retorno**; el `.bak` es la salida.
6. Un `secret set` de prueba en una variable inocua, y verificar que los dos nodos la
   reciben.

⚠️ **A partir de la migración, la contraseña es lo único que puede re-sellar.**
Perderla no solo impide administrar: impide **rotar una variable o sumar un aparato
al namespace**, porque la CEK vive cifrada bajo ella. La salida sería pedir
credenciales nuevas a su proveedor y reconfigurar. Gestor de contraseñas **y** copia
fuera de línea, antes del paso 5.

### 6.1. Administrar después del sellado: TODA escritura pide la contraseña

> ⚠️ **DEROGADO por el §8** (2026-08-20): desde v5 **escribir no pide nada** y la frase
> queda para VER. Esta sección describe cómo fue entre el 2026-08-18 y esa fecha.

Lo que cambia en el día a día, y costó dos versiones descubrirlo entero: desde el
sellado, guardar una variable ya no es «escribir un valor». Hay que abrir la copia
maestra para poder envolver la nueva a cada aparato, y eso solo lo hace la contraseña.
Las tres interfaces la piden ahora (0.39.5):

| Interfaz | Cómo la pide |
|---|---|
| **CLI** | pregunta al vuelo, y solo si el perfil tiene contraseña. Lee de `/dev/tty`, no de la entrada estándar, para que `cat .env \| dotrino-vault secret import <ns>` siga funcionando. Por ssh hace falta `-t`. |
| **TUI** | la de la sesión, la misma que se escribió al desbloquear |
| **Consola web** | un campo que aparece **solo cuando la bóveda la pide**, y viaja DENTRO del mismo sobre sellado que los valores |

Dos cosas que no son lo mismo y se confunden:

- **El candado** (`unlock`/`lock`) decide si esta consola puede administrar. Es de la
  consola: los aparatos siguen recibiendo su configuración con el perfil bloqueado.
- **La contraseña en la escritura** es material de llave, no un permiso. Aunque el
  perfil esté desbloqueado, guardar una privada la vuelve a pedir.

**Borrar no la pide**: tirar un sobre no obliga a abrirlo.

**Cambiar la contraseña** es quitarla y volver a ponerla (`dotrino-vault profile
password rm`, luego `profile password`). Las dos operaciones **re-sellan** la copia
maestra —descifrar con la vieja, cifrar con la nueva—, así que hay que dar la actual:
sin ella los secretos quedarían ilegibles. Un perfil **sin** contraseña sigue
funcionando y sigue sellando; lo que cambia es que la copia maestra pasa a cerrarse con
la llave de la máquina, que es la protección de antes de todo esto.

## 7. Decisiones abiertas

1. **Rotar el `ns` al expulsar: RESUELTO** — se rota (CEK nueva, valores recifrados),
   y si el perfil está bloqueado el cajón queda marcado y la siguiente escritura
   desbloqueada lo salda. Quitar solo la envoltura no bastaba: quien guardó la CEK
   seguiría abriendo lo que se escriba mañana. Lo que no se deshace, y no se promete,
   es lo que ya leyó.
2. **La contraseña por el disco** — llega al daemon por un archivo 0600 que se borra
   al consumirse. No es peor que hoy (`unlock` ya va por ahí), pero con la contraseña
   convertida en material de llave el precio sube. Un socket sería mejor.
3. **`profiles.json` en claro con el verificador dentro** (§4.2) y el **mínimo de 4
   caracteres** (§4.3). Mientras sigan así, la fuerza de todo esto es la de la frase
   que elija el dueño, no la del cifrado.
4. **La maestra sigue en esa máquina.** Este trabajo protege los secretos de servicio,
   que son rotables. No cambia que quien controle el VPS pueda suplantar al vault
   frente a la consola (§3, límite 3).

## 8. La frase, solo para VER (acordado e IMPLEMENTADO el 2026-08-20)

> Pedido del dueño: **no teclear la contraseña del perfil en el navegador**, y poder
> administrar sin ella también desde la TUI. La frase deja de ser un requisito para
> escribir y pasa a significar **una sola cosa: ver los valores**.

**Implementado en `dotrino-vault` 0.42.0** (`secrets.json` v5), con
`@dotrino/identity` 0.55.0 (acta v2 con llave de sellado, `openSealedValue`) y
`@dotrino/vault` 0.27.0 (el agente comprueba la procedencia). **El §6.1 de arriba queda
DEROGADO**: describía el estado anterior, en el que toda escritura pedía la contraseña.
Se conserva porque explica de dónde viene esto y qué se deshizo.

### 8.1. Por qué se puede: cifrar es una capacidad PÚBLICA

Sellar no necesita ningún secreto de la bóveda. `sealer.wrapFor` es `makeGeneration`
de `@dotrino/identity` (`vault/content.js:84`): recorre los miembros y de cada uno usa
**solo su `encPub`**, que vive en claro en el acta; y la CEK la fabrica ella misma con
`makeContentKey`. Ni una línea toca la frase.

Lo que la exige hoy es **la copia maestra**, que es AES simétrico bajo la llave
derivada de la contraseña (`sealer.js`, `openMaster`/`sealMaster`): `_putRaw`
(`secretsStore.js:278-282`) la abre para sacar la CEK del cajón y la vuelve a cerrar.
O sea, la frase la pide **el almacén de CEK**, no el sellado. Es una decisión del
§2.2, no una necesidad criptográfica.

### 8.2. Tres destinatarios en vez de dos

La CEK de cada cajón se envuelve a:

| Destinatario | Para qué | Abre con |
|---|---|---|
| los **servicios** del `ns` | consumir su configuración | su propia privada |
| los **aparatos de administración** — miembros sin CN y con `encPub` (`acta.js:455`) | leer, auditar y **revertir** desde la consola | la llave del aparato, que **no sale de él** |
| la **copia de recuperación**, bajo la frase | el día que no quede ningún aparato | la frase, en la máquina del dueño |

La regla de siempre no cambia y es la que sostiene todo: **la CEK nunca se envuelve a
la llave de esta bóveda** (`test/sealer.test.mjs:100`).

### 8.3. Qué pide qué, y por qué no es lo mismo en cada sitio

| | Poner / cambiar una variable | Ver su valor |
|---|---|---|
| **Consola** (tu aparato) | sin frase | **sin frase**: la abre la llave del aparato |
| **TUI / CLI** (la máquina de la bóveda) | sin frase | **con frase**, y no hay otra manera |

Esa asimetría no es una inconsistencia, es la definición del diseño: en la máquina de
la bóveda, «la llave del aparato» y «una llave que vive en ese disco» son la misma
cosa. Si desde ahí se pudiera ver sin frase, una instantánea del disco vería todo y
esto no valdría nada. Por eso ahí la frase es el único camino a los valores — y solo a
eso.

### 8.4. El histórico, para revertir

Cada escritura conserva el **sobre anterior** en una lista append-only con quién y
cuándo, firmada. Tres consecuencias:

- La bóveda **escribe el histórico sin poder leerlo**. Auditar no lo hace ella: lo hace
  el aparato que puede abrir. Ella solo garantiza que la lista está completa y firmada.
- **Revertir es una escritura normal**: el aparato abre el sobre viejo con su llave y lo
  vuelve a guardar. Tampoco pide frase.
- Un histórico de secretos es también un **pasivo** —mantiene vivas credenciales
  viejas—, así que lleva tope (N versiones o M días) y un «purgar» explícito.

### 8.5. Lo que se arregla de paso

- Desaparece `sessionPwd` (`src/tui/app.js:141-146`), que hoy guarda la contraseña en
  RAM **toda la sesión de la TUI** solo para poder sellar. Contradice al §2.3 («por
  operación, no una sesión») y era el precio de exigir la frase al escribir.
- Se cae casi entero el punto 2 de §7 (la frase llegando al daemon por un archivo
  0600): con la escritura sin frase, solo queda el camino de *ver*.

### 8.6. El precio, dicho claro

1. **El aparato de administración pasa a poder LEER.** Hoy no puede
   (`docs/consola-remota.md:50`: valor nuevo «sí, **a ciegas**»). Es el cambio, no un
   descuido: la capacidad de leer se muda de *una frase que se teclea en cualquier
   parte* a *una llave que no sale del aparato*. Consecuencia: **perder un aparato de
   administración pasa a equivaler a perder los secretos**, así que revocarlo tiene que
   rotar de verdad — que ya es la regla desde 0.39.
2. **Escribir sin frase** deja que quien controle la máquina de la bóveda **inyecte**
   configuración a un servicio (no que lea la vieja). No es una puerta nueva —§3,
   límite 3, ya dice que con la maestra ahí se puede suplantar a la bóveda— pero queda
   escrito.
3. **Rotar recifrando lo existente** y **pasar una privada a pública** siguen exigiendo
   leer: sin frase, solo desde un aparato de administración.

### 8.7. Los sobres los hace la BÓVEDA, no la consola

Lo que viaja no cambia: la consola manda el valor **sellado con la llave de contenido
del perfil**, como hoy (`identity.sealContent` → `openContent` en la bóveda), y es la
bóveda la que abre ese sobre y **sella al destinatario**. Las `encPub` de los miembros
**no salen del acta** y la consola nunca recibe una lista de a quién hay que sellarle.

Por qué se queda así:

- **Un solo sitio con criptografía** (`sealer.js`), que es lo que hace que se pueda leer
  entero y probar con un sellador falso.
- **La consola no elige destinatarios.** Si sellara ella, podría envolver a una llave
  suya —o a una ajena— y la bóveda no tendría cómo notarlo. Sellando la bóveda, la
  lista sale siempre del acta vigente, con las revocaciones ya aplicadas.
- **Repartir, rotar y re-envolver** siguen del lado de la bóveda, que es donde está el
  estado (miembros, generaciones, deudas pendientes).

Y el límite honesto, que ya existe hoy (§1, primera fila de la tabla): **la bóveda ve
en claro el valor NUEVO en el momento de escribirlo** — tiene que verlo para poder
sellarlo. Lo que el sellado protege es el **reposo** y lo **ya guardado**, no ese
instante. Quien no quiera ni eso está pidiendo la tercera fila del §3 (claro solo en la
consola), que es otro diseño.

**Consecuencia técnica: una generación por escritura.** La bóveda no puede reutilizar
la CEK de un cajón, porque no puede abrir ninguna envoltura para recuperarla. Así que
cada escritura crea una CEK nueva, la envuelve a los destinatarios del §8.2 y cifra el
valor con ella; el llavero crece una entrada por escritura. Hay que **recoger las
generaciones** que ya no referencia ningún valor ni ninguna entrada del histórico —el
mismo barrido que el tope del §8.4.

**Leer va al revés**: la bóveda reenvía el sobre y la envoltura de ese aparato, y abre
el aparato. Ni una llave privada viaja en ninguna dirección.

### 8.8. Una llave propia para FIRMAR los sellados

La bóveda firma cada sobre con una llave **suya, dedicada a eso**, y no con la maestra.
La clave del asunto es que **firmar no es leer**: una llave de firma no abre ningún
valor, así que puede vivir cifrada en reposo con la llave de la máquina y usarse **sin
la frase y sin abrir la copia maestra**. No hay nada que desbloquear para sellar, que
es justo lo que pide el §8.

**De dónde saca su autoridad: un certificado emitido UNA vez por la maestra.** Es la
misma maquinaria que ya valida a cualquier aparato (`verifyChain` con
`trustedIssuer: master`), así que no hay que tocar el esquema del acta ni subirle la
versión, y la renovación y la revocación ya existen. Se descarta meterla como miembro
con CN: `checkShape` reserva los CN para servicios y no le dejaría capacidades de
aparato.

Lo que se gana:

1. **Higiene de la maestra.** La raíz de confianza deja de firmar una operación
   rutinaria y frecuente. Firma el acta y el certificado del sellador, y poco más.
2. **Procedencia en reposo.** Hoy un sobre tiene integridad (AES-GCM) pero **no
   origen**: como envolver solo necesita públicas, *cualquiera* puede fabricar un sobre
   válido para un servicio. La firma dice cuáles salieron del flujo de administración
   de esta bóveda.
3. **Histórico verificable**, que es lo que hace que revertir sea de fiar: cada versión
   guardada viene firmada y se comprueba antes de restaurarla.
4. **Rotación barata**: si la llave de sellado se compromete, se rota su certificado sin
   tocar la identidad del perfil.

Y lo que **no** da, dicho antes de que alguien lo suponga: la llave vive en la máquina
de la bóveda, así que quien controle esa máquina también puede firmar. Una firma suelta
no impide inyectar configuración (§8.6, punto 2). Lo que la convierte en **detección**
es **encadenar**: `seq` monotónico y hash de la entrada anterior, y el aparato de
administración recordando el último `seq` que vio. Entonces una reescritura silenciosa
sale como un hueco o como una bifurcación, en vez de no salir. Sin cadena, esto es
higiene y procedencia; con cadena, además, se nota.

Alcance: además del daemon, el agente (`@dotrino/vault`) tiene que **verificar** la
firma del sobre que recibe, no solo la del cuerpo del bundle.

### 8.9. La llave de sellado ROTA CON EL ACTA

Mejor que un certificado con vida propia (§8.8): la llave de sellado **vive en el acta y
cambia con ella**. Cada acta nueva nombra una llave de sellado nueva, y el acta —como
siempre y sin excepción— **la hace y la sella únicamente la maestra**. La cadena de
autoridad queda en una línea: *maestra → acta (`seq` + `prev`) → `sealPub` → sobres*. La
llave de sellado nunca se autoriza a sí misma; lo único que puede hacer es firmar.

Lo que sale gratis de acoplarlas:

- **Rotación sin ceremonia.** Entra o sale un aparato → acta nueva → llave nueva. No hay
  un calendario de rotación que mantener ni un certificado que renovar.
- **Un sobre dice CUÁNDO se selló, en términos de membresía.** Firmado con la llave del
  acta N ⇒ sellado mientras la membresía era N. Eso hace visible lo que hoy no se ve: un
  valor sellado a un aparato **después** de haberlo expulsado, o un llavero que se quedó
  atrás respecto del acta.
- **La ventana de una llave filtrada se cierra sola.** Los sobres nuevos tienen que ir
  firmados con la llave del acta vigente; en cuanto hay acta nueva, la vieja ya no puede
  producir nada que parezca fresco.

Dos cosas que hay que resolver al implementarlo:

1. **Los sobres viejos siguen teniendo que verificar.** Rotar no los re-firma —eso sería
   recorrer todos los secretos en cada cambio de membresía—, así que el acta lleva un
   registro compacto de las llaves anteriores (`sealKeys: [{ seq, pub }]`), que se poda
   junto con el tope del histórico (§8.4).
2. **Sube la versión del acta** (`ACTA_V`, hoy 1) en `@dotrino/identity`. Es un pilar, así
   que el cambio va limpio en los dos lados y se publica; no hay retrocompatibilidad que
   cuidar.


### 8.10. Cómo quedó, archivo por archivo

| Dónde | Qué hace ahora |
|---|---|
| `@dotrino/identity` `vault/acta.js` | acta **v2**: `sealPub` + `sealSince` + `sealKeys` (el tramo de cada llave anterior) y `sealKeyAt(acta, seq)`. Las v1 se siguen leyendo y ascienden solas |
| `@dotrino/identity` `vault/core.js` | `setSealKeyProvider` (se llama al sellar CADA acta), `rotateSealKey`, `openSealedValue` (un aparato abre lo que le sellaron, con su propia llave) |
| `dotrino-vault` `src/sealKey.js` | el llavero de sellado de la bóveda: estrena llaves y firma con la que el acta nombra. **No abre nada**, así que se usa sin la frase |
| `dotrino-vault` `src/secretsStore.js` | **v5**: sin copia maestra, con par de recuperación, una generación por escritura, recogida de generaciones, histórico y `reveal`/`revert` |
| `dotrino-vault` `src/vault.js` | destinatarios (servicios + aparatos que administran + recuperación), firma de cada sobre, y el acta viajando con el bundle |
| `dotrino-vault` `lib/src/admin.js` | **sin** `var.reveal`/`var.history` (quitadas 2026-08-22): un aparato que administra no tiene sobres de lo privado; ver/histórico/volver son de la bóveda en su máquina |
| `dotrino-vault` `lib/src/service.js` | el agente abre **por generación** y comprueba la **procedencia** de cada sobre |
| `dotrino-vault` `web/` y `src/tui/` | se va el campo de la contraseña de la consola; la TUI conserva ver con contraseña |
| CLI | `secret show` · `secret history` · `secret revert` · `secret settle` |

**Orden de despliegue:** primero los **agentes** (`@dotrino/vault` ≥0.27.0, que sabe abrir
por generación), después el **daemon**, y solo entonces la **conversión** a v5.

La conversión, además, **deja UNA sola generación por cajón** —convertir es un acto único
y ahí la bóveda tiene los valores delante, así que no necesita recuperar ninguna llave—,
y eso es justo lo que un agente sin actualizar espera. O sea que convertir no apaga a
nadie: lo que rompe a un agente viejo es la **primera escritura posterior**, que sí
estrena generación. Hay un test que lo fija (`secrets-store.test.mjs`).

### 8.11. Quien reparte la llave a un aparato nuevo es el SERVICIO

> Decidido con el dueño el 2026-08-22, al ver que un content node recién enrolado
> arrancaba repitiendo *«no key to open CONTENT_S3_KEY_ID: this device has no wrapping
> for its drawer»*. Cierra el §8.7 por el lado que faltaba.

**El problema.** Una variable se sella al escribirla, para los miembros que había
entonces. Un aparato que entra después no tiene envoltura de ella — y la bóveda no se la
puede hacer, porque envolver exige **abrir** la llave y abrirla pide la frase. Así que un
servicio recién enrolado se queda sin configuración.

**Las dos salidas malas, y por qué se descartaron.**

| Idea | Por qué no |
|---|---|
| Que el admin console mande la frase para abrir la bóveda | es teclear la contraseña del perfil en un navegador, que es justo lo que el §8.1 existe para evitar |
| Un **depósito de llaves privadas** en la bóveda, para asignarle una al que llegue | para poder entregarla sin la frase, esa privada tiene que abrirse **sin** la frase → es una segunda llave de recuperación sin contraseña, y quien copie el disco lee todo. Propuesta del dueño y descartada por él mismo al ver el precio |

**La salida buena: que reparta quien ya tiene la llave abierta.** El servicio que consume
ese cajón la abre en cada arranque. Re-envolverla para otro miembro **no le añade ningún
poder** — ya podía leer eso —, así que es el único que puede hacerlo sin que nadie ceda
nada:

```
bóveda → servicio   { owner, gen, TU envoltura, a quién, ACTA }   firmado por la maestra
servicio            comprueba la firma · comprueba el acta · saca del ACTA la pública
                    del destinatario · abre con su llave · envuelve
servicio → bóveda   { la envoltura nueva }                        firmado por él
bóveda              putWrap: la guarda
```

**Los cuatro cerrojos, y ninguno sobra:**

1. **La petición va firmada por la maestra.** Un mensaje suelto por el proxy no mueve nada.
2. **El acta viaja dentro y se comprueba aparte**, también firmada por la maestra.
3. **La pública del destinatario se saca del ACTA, nunca del mensaje.** Si se cogiera del
   mensaje, quien lo mandara —incluida una bóveda comprometida— podría hacer que el
   servicio envolviera la llave para una pública suya.
4. **El destinatario tiene que ser de ESE cajón** (`cn === ns`): un servicio no puede
   ampliar el acceso a nada que no sea lo suyo.

Y del lado de la bóveda, **`putWrap` solo AÑADE, nunca pisa** (lo pidió el dueño pensando
en un servicio comprometido): si pudiera reemplazar, dejaría sin leer a los demás miembros
metiéndoles una envoltura basura. Reemplazar es cosa de la bóveda, y pasa por escribir,
que estrena generación entera.

**Si no hay nadie encendido que la reparta, la deuda se queda A LA VISTA** —
`incompleteMembers()` dice qué aparato no puede abrir qué variables — y **abrir la bóveda
la salda**: con la frase delante, `resealAll` rehace el llavero entero y lo deja
exactamente con lo que dice el acta (crea lo que falta, reemplaza lo que alguien metiera
mal y tira lo que sobra).

> **Todo esto existe SOLO porque hay contraseña.** Un perfil sin frase abre su propia
> llave de recuperación y se envuelve solo; no hay deuda que saldar ni nada que delegar.
> Es exactamente por eso que el trabajo vale: el caso con frase es el de producción.

#### Hacia dónde crece: consumidores EFÍMEROS

> Anotado por el dueño el 2026-08-22 como caso a revisar, no implementado.

*«Quiero meter `.env` en funciones lambda: nacen y reciben variables de un servicio
delegado.»* Es este mismo mecanismo, con una diferencia que hay que resolver antes:
**una lambda no puede estar en el acta**, porque nace después de que la maestra firmara y
muere en segundos.

Lo que haría falta, y por eso no está hecho: que el acta pueda **avalar a una clase de
efímeros bajo un `cn`** —un servicio que puede envolver para llaves recién nacidas que él
mismo acredita, con vida corta— en vez de a un miembro concreto. El cerrojo 3 de arriba
se vuelve entonces *«la pública viene del aval del servicio, y el aval caduca»*, que es
un modelo distinto y hay que pensarlo con calma: es abrirle a un servicio la puerta de
decidir quién lee lo suyo.

## 9. Nada en claro en el disco, y quién no recibe sobres (2026-09-02)

> Dos preguntas del dueño mirando el directorio de datos: *«ninguna información debería
> estar en claro»* y *«¿dónde se almacena la llave de comunicación? ¿se puede garantizar
> que esa llave no reciba ningún sobre?»*.

### 9.1. Lo que quedaba en claro, y por qué nadie lo veía

La bóveda cifraba en reposo sus **almacenes** desde hacía meses (`identity.json`,
`vault.json`, `threads.json`, `secrets.json`). Tres cosas quedaban fuera porque no se
contaban como «datos»:

| Qué | Qué llevaba dentro |
|---|---|
| **el canal local con la CLI** (`state.json`, `acta.json`, `secret-request.json`…) | **la contraseña del perfil**, el **valor** de cada variable que guardas, el acta con sus permisos, el volcado de certificados |
| **`transport.json`** | la **privada** del par de transporte de `@dotrino/proxy-client` |
| **`activity.log`** | el mapa de la cuenta: qué aparatos, con qué permisos, contra qué cajones y a qué hora — y creado **0664**, legible por cualquier usuario de la máquina |

El canal es el que más duele: el daemon y `dotrino-vault` no hablan por un socket, se
dejan archivos JSON. Que fueran efímeros no salvaba nada — se escriben en el disco igual,
y un `rm` no borra lo que ya se copió.

Desde **0.89** los tres van por el mismo cifrado en reposo (`src/ipc.js` para el canal;
la bitácora **línea a línea**, que es lo que deja seguir añadiendo). Desde **0.90**, lo
que ya estaba escrito **se convierte al arrancar**: cifrar solo lo nuevo deja el disco en
claro durante meses.

**Por qué en reposo y no en un sobre.** Un sobre se cierra contra la pública de quien va a
abrirlo, y aquí el que abre es la CLI del propio usuario, que no tiene llave propia;
inventarle una la dejaría en el mismo disco y al lado. **El sobre es para lo que VIAJA;
para lo que se queda en la máquina, el reposo.** Y el acta que sí viaja **no se puede
sellar**: el proxio tiene que leerla para comprobar que quien habla es miembro
(`verifyActaMembership`), así que va firmada y legible, que es justo su trabajo.

Lo único que queda en claro, y con motivo:

| Archivo | Por qué |
|---|---|
| `atrest.salt` | es el salt DEL cifrado: no puede ir cifrado con él |
| `atrest.machine` | un SHA-256 del material de la máquina; **avisa** de un cambio de máquina, no abre nada |
| `atrest.json` / `atrest.kek` | qué proveedor cifra, y la DEK envuelta por él |
| `vault.lock` | el candado entre procesos: se lee antes de tener clave |
| `key.json` | la **pública** que dice de quién es la carpeta; hay que leerla antes de poder descifrar (`keyowner.js`) |
| `prefs.json` | el idioma de la interfaz |

`dotrino-vault atrest status` lista ahora las dos mitades: lo cifrado **y lo que quedó en
claro**. Es como apareció `profiles.json.pre041.bak`, un respaldo que una versión vieja
dejó en texto plano **con el verificador de la contraseña dentro**, meses después de que
su migración terminara.

Y hay un smoke que lo afirma sobre una bóveda de verdad: `dotrino-test/smoke/reposo.mjs`
la hace trabajar, le recorre el disco entero y busca el valor, la contraseña y cualquier
`"d":` de un JWK por todos los bytes.

### 9.2. La llave de comunicación: dónde vive y por qué no recibe sobres

**Dónde:** `p/<perfil>/commkey.json`, cifrada en reposo con la llave de la máquina y en
0600. Dentro, un par ECDSA P-256 (`{ v, pub, priv, createdAt }`). **No** va bajo la
contraseña, y es a propósito: es la que firma cuando el perfil está CERRADO — si
necesitara la frase, una bóveda cerrada no existiría en la red (ver `src/commKey.js`).

**Por qué la pregunta importa:** un sobre dirigido a ella sería una forma de leer secretos
**sin abrir la bóveda**, que es exactamente lo que el candado impide. Y al revés que la
llave de SELLADO —que no es miembro del acta, y por eso su garantía es que no existe
camino—, **esta sí es miembro**, así que hace falta decir algo más fuerte que «no está en
la lista».

Son tres cerrojos, y ninguno es un accidente:

1. **No hay a dónde envolver.** Un sobre se cierra contra una pública de **cifrado** y
   esta es un par de **firma**: no tiene `encPub` en el acta, y `recipientsFor` filtra por
   `encPub`. Sin ella, no hay envoltura posible aunque alguien la pidiera.
2. **El acta no le reconoce `secrets`.** Entra con `cn: 'vault'` y `caps: ['sign']`. Este
   cerrojo es el que faltaba: `nsMembers` miraba **solo el `cn`**, y `cn` es texto libre —
   un cajón llamado `vault` (nombre perfectamente válido) la contaba entre sus dueños. No
   llegaba a recibir sobre por el cerrojo 1, pero la salvaguarda era estructural por
   casualidad: bastaba apuntarle una `encPub` para envolverle la llave a la llave que
   firma con la bóveda cerrada. Desde 0.89 se pregunta por `memberCanReadSecrets`.
3. **No puede conseguir una `encPub`.** La única puerta es `handleEncKey`, que exige una
   cadena de certificados válida con scope `vault:secrets:<ns>` **y** `memberCanReadSecrets`.
   La llave de comunicación **no tiene certificado** —entra por `admitMember`, no se
   enrola— y no tiene `secrets`. Dos noes independientes.

Y tampoco entra por las otras dos puertas: `adminDevices` exige `!m.cn` (ella lleva uno) y
`cosealerMembers` exige `sealer` + `encPub` (no tiene ninguno de los dos).

Comprobado, no razonado: `smoke/reposo.mjs` crea un cajón llamado **`vault`** —su propio
`cn`— y afirma que su llave no aparece en **ninguna** envoltura de **ningún** cajón.

### 9.3. La bóveda CERRADA, medida (2026-09-02, vaultd 0.93)

Auditoría con los dos perfiles bloqueados, preguntando lo único que importa: **qué consigue
quien tiene esta máquina y el disco**. No razonada — probada, abriendo cada cosa con la
llave de la máquina a ver si cede.

| Llave | Cerrada con | Con el disco y el perfil cerrado |
|---|---|---|
| **la maestra** (`keypair`) | la contraseña | **no cede** — ni firma ni se recupera |
| **`#recovery`** | la contraseña | **no cede** — el AES-GCM no autentica con la llave de máquina |
| **`enc-keypair`** | la llave de máquina | cede |
| **`sealkeys.json`** | la llave de máquina | cede, **a propósito** |
| **`commkey.json`** | la llave de máquina | cede, **a propósito** |

**Lo que aguanta, y es lo que sostiene el modelo.** `#recovery` es la envoltura que llevan
TODOS los sobres, así que si cediera, los cajones se abrirían enteros con el disco y el
sellado no valdría nada frente a un robo. No cede: está bajo la contraseña. Se comprobó
descifrando `recovery.priv` con la llave de máquina — la autenticación GCM falla.

**`enc-keypair` cede, y hay que decir exactamente qué abre.** Es la llave de cifrado del
perfil, y su privada vive bajo la llave de máquina. **No abre los cajones de secretos**: no
hay ni un sobre dirigido a ella (comprobado sobre los dos perfiles, con 0 y 4 destinatarios,
y ninguno es ella), porque la bóveda no se envuelve a sí misma — envolverle la CEK sería
devolverle la capacidad de leerlo todo. Lo que sí abre es el CONTENIDO sellado a este
perfil. Sigue siendo la pieza que falta cerrar bajo la contraseña, y lo que lo frena es
decidir si el almacén sirve con el perfil cerrado: hoy sirve, y por eso su llave no puede
pedir una frase que no está puesta.

**Las otras dos ceden a propósito, y es el precio de servir cerrada.** La de sellado firma
lo que la bóveda sirve; la de comunicación la identifica en el proxio. Si pidieran la frase,
una bóveda cerrada no existiría en la red ni podría atender a sus aparatos — que es
justamente lo que el candado NO debe romper (el candado es de la consola). La de
comunicación va acotada por el acta (`cn: 'vault'`, solo `sign`): con ella se habla por la
bóveda, no se firma por la persona ni se lee nada.

**Y el marco de siempre, que no cambia:** el cifrado en reposo no protege contra una copia
del DISCO ENTERO, porque su material vive en ese mismo disco. Sube el listón de «copiar un
archivo» a «tener tu máquina». Cerrarlo de verdad pide que la clave no esté aquí, y para eso
está el proveedor KMS (`atrest rekey`, `docs/llaves-de-hardware.md`).
