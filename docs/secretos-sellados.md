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

- Es **por operación**, no una sesión. Hoy `unlocked` es un `Set` que dura hasta
  que alguien llame a `lock` (`profiles.js:233`); eso está bien para la puerta de
  administración, pero la **llave derivada** no puede quedarse ahí — si se queda
  en RAM indefinidamente, todo este diseño no sirve para nada.
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
