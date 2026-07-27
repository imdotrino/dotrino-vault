# Vincular una cuenta a un vault — los dos caminos

> **Decidido por el dueño el 2026-07-27.** Vincularse a una bóveda tiene **exactamente dos
> caminos**, y **no existe fusionar cuentas**. Este documento manda sobre el tema; el modelo
> de fondo (acta, master, capacidades, CEK) está en
> [`acta-de-perfil.md`](./acta-de-perfil.md) y no cambia.

Al conectar un aparato con una bóveda, o bien **la cuenta del aparato pasa a vivir en la
bóveda**, o bien **se crea en el aparato una cuenta nueva: la que ya vive en la bóveda**.
Nada más. No hay un tercer camino que junte dos cuentas en una.

---

## 0. Decisiones

| # | Decisión |
|---|---|
| **V1** | **Dos caminos y solo dos.** (A) la cuenta del dispositivo entra a la bóveda como una cuenta nueva de esa bóveda; (B) la cuenta de la bóveda se materializa en el dispositivo como una cuenta más. |
| **V2** | **No existe el merge de cuentas.** Dos cuentas nunca se convierten en una: ni al vincular, ni después. Lo que sí existe —**en otra fase**— es **mover el contenido** de una cuenta a otra y, si quieres, borrar la de origen (§4). Eso mueve *cosas*, no identidades. |
| **V8** | **Mover contenido es una operación LOCAL e independiente en cada lado.** Se hace donde las dos cuentas ya viven en la misma máquina: en el dispositivo entre dos perfiles del dispositivo, en la bóveda entre dos perfiles de la bóveda. **No viaja por la red y no hay protocolo nuevo**; son dos implementaciones separadas que no se sincronizan entre sí. |
| **V3** | **Vincular es elegir de qué cuenta estás hablando**, no juntar lo que hay a los dos lados. La pregunta que hace la UI es «¿qué cuenta?», no «¿qué hago con las dos?». |
| **V4** | **Lo que pertenece a un perfil es la LLAVE, no la máquina.** Un aparato puede tener varias llaves —una por cuenta— y por eso puede tener varias cuentas a la vez (multi-perfil). La regla de `acta-de-perfil.md §2.4.3` se lee así: *una llave está en un solo perfil*. |
| **V5** | **Ninguna cuenta que ya existe se sobrescribe jamás.** El camino B **crea una cuenta nueva** en el dispositivo (con llave nueva); nunca reemplaza la que estabas usando. |
| **V6** | **El contenido no se re-cifra al vincular.** En A es una copia byte a byte (misma CEK, mismo perfil); en B no se mueve nada (solo se envuelve la CEK para la llave nueva). |
| **V7** | **La intención viaja firmada en el emparejamiento** (`intent`). Sin intención explícita no se toca ninguna cuenta existente: el emparejamiento se detiene y pregunta. |

---

## 1. Vocabulario (para que no se confunda nada)

- **Cuenta = perfil = acta.** Una cuenta es un acta: un conjunto de llaves miembro más la
  política firmada que dice qué puede cada una.
- **`profileId` = pubkey de la llave génesis.** Es el nombre de la cuenta y **no cambia
  nunca**. Es lo que el mundo de afuera conoce: la reputación, los contactos y todo lo que
  esa cuenta firmó cuelgan de ahí.
- **Miembro = una LLAVE**, no un aparato (V4).
- **Master (`sealer`) = la única llave que sella el acta.** La intención de siempre es que
  termine siendo la bóveda (D5).
- **Un dispositivo es multi-perfil** (`@dotrino/identity`, una llave por perfil) **y la
  bóveda también** (`dotrino-vault/src/profiles.js`: un subdirectorio y una llave por
  perfil, todos corriendo a la vez en el mismo daemon).

Así que «vincular» es siempre: **una llave de aquí entra al acta de allá, o al revés.**

---

## 2. Camino A — la cuenta del aparato pasa a vivir en la bóveda

> *«Esta cuenta que tengo en el teléfono, que la guarde mi computadora.»*

**Lo que conserva:** el `profileId`. La cuenta **sigue siendo la misma** para todo el mundo
— la misma reputación, los mismos contactos, lo mismo firmado. No hay nada que migrar.

**Lo que cambia:** quién sella. La bóveda entra como miembro y recibe el master; el teléfono
se queda como un miembro más de su propia cuenta.

**Para la bóveda es una cuenta NUEVA**: aparece un perfil más en su lista (`profile ls`),
con su propio directorio y su propia llave. Lo que no es nuevo es la cuenta en sí: la bóveda
la está **adoptando**, no creándola.

### Orden exacto

| Paso | Quién | Qué pasa |
|---|---|---|
| 1 | bóveda | abre el emparejamiento y muestra el QR (igual que hoy). |
| 2 | teléfono | escanea y manda el `ENROLL` con **`intent: 'adopt'`** + su `profileId`. |
| 3 | humano | teclea en la bóveda los 6 dígitos que muestra el teléfono. |
| 4 | bóveda | comprueba el compromiso del código, **crea un perfil vacío** y responde con su `{pub, encPub}` **y el código** (así el teléfono sabe que a esta bóveda la aprobó una persona, y no una cualquiera que pasaba por el proxy). |
| 5 | teléfono | sella **un solo `seq`**: `admit` de la bóveda + `wrap` de la CEK + `handover` del master a la bóveda (§2.1.3 del acta). Manda el acta sellada. |
| 6 | bóveda | se ve como `sealer`, guarda el acta en su perfil nuevo y **re-emite los certs de todos los miembros** (D9) → `seq+1`. |
| 7 | teléfono | adopta esa acta (`sealedBy` = el `sealer` que él mismo nombró: encaja sin excepciones). |
| 8 | los dos | **copia del contenido** teléfono → bóveda, reanudable y en segundo plano. Mismo perfil, misma CEK: **se copia cifrado tal cual, sin descifrar ni re-cifrar**. |

Del paso 5 al 6 no hay ventana rara: admitir y traspasar van en el **mismo `seq`**, que es la
regla que ya existe justamente para esto.

### Requisito

**Solo puede hacerlo el master de esa cuenta.** Si el teléfono ya no sella (la cuenta ya vive
en otra bóveda), no puede regalar lo que no tiene: el traspaso se hace **desde la bóveda que
manda hoy** (es el caso «mudarse de PC», que ya está cubierto por el mismo `handover`).
Error explícito: `no-eres-el-master`, y la copy lo dice en llano.

---

## 3. Camino B — se crea en el aparato una cuenta nueva: la de la bóveda

> *«En este teléfono quiero también la cuenta que ya vive en mi computadora.»*

**Lo que conserva:** todo lo que ya tenías en el teléfono. **Nada se toca.** La cuenta que
estabas usando sigue ahí, con su llave, su contenido y su acta.

**Lo que pasa:** el teléfono **crea una cuenta más** (perfil nuevo, **llave nueva**) y **esa
llave** —no la que ya usabas— es la que entra al acta de la bóveda. Al terminar, el
conmutador de perfiles muestra una entrada más.

### Orden exacto

| Paso | Quién | Qué pasa |
|---|---|---|
| 1 | teléfono | **crea el perfil nuevo** y su llave (`createProfile`), antes de hablar con nadie. |
| 2 | bóveda | abre el emparejamiento y muestra el QR. |
| 3 | teléfono | manda el `ENROLL` con **`intent: 'join'`**, firmado con la **llave nueva**. |
| 4 | humano | teclea los 6 dígitos en la bóveda. |
| 5 | bóveda | comprueba el código, emite el cert, **admite la llave nueva** en su acta y le **envuelve la CEK** → el aparato ve el contenido que ya existía. |
| 6 | teléfono | adopta el acta en **ese** perfil nuevo (que estaba vacío) y listo. |

**No se mueve ni un byte de contenido**: la cuenta ya vivía en la bóveda y el aparato pasa a
leerla ahí. Lo único que viaja es la CEK envuelta a la llave nueva.

**Continuidad:** aquí **no hace falta** certificado de continuidad. La llave nació hace un
segundo y no tiene pasado que salvar; ya no se manda (0.34.0).

> ⚠️ **Y con eso el certificado de continuidad se queda sin ningún caso de uso.** Existía para
> «una identidad que ya existía se une a otro perfil», que es justo lo que el modelo de dos
> caminos elimina: en A la identidad **es** la cuenta (no hay nada que puentear) y en B la
> llave es nueva (no hay pasado). Queda el código en su sitio —es inofensivo y puede servir en
> el protocolo del camino A—, pero **hoy no lo llama nadie**. Decidir si se borra.

---

## 4. Fusionar cuentas no existe; mover contenido sí (y es OTRA FASE)

**Decidido por el dueño (2026-07-27).**

### 4.1 Las identidades no se funden

Si tienes una cuenta en el teléfono y otra en la bóveda, **siguen siendo dos cuentas**. Se
elige de cuál se está hablando (camino A o camino B) y la otra sigue su vida. Si quieres, la
otra también puede tener bóveda: repites el camino A con ella y la computadora guarda las dos
(es multi-perfil).

Por qué, dicho una vez para no volver a discutirlo:

- **Una de las dos tendría que morir.** El nombre de una cuenta es la pubkey de su génesis;
  no hay forma de que dos nombres sean uno. Fundirlas es siempre *matar una*.
- **Y al morir se lleva cosas que no son nuestras.** Lo que le calificaron, los que la tenían
  guardada de contacto y todo lo que firmó apuntan a ese nombre. Repararlo pide reenvíos
  firmados, resolución de alias en la reputación y un aviso a cada contacto: mucha maquinaria
  nueva para un gesto que se hace una vez en la vida.
- **No tiene vuelta atrás.** No hay «des-fundir».

### 4.2 Lo que sí habrá: mover el contenido de una cuenta a otra

Es lo que la gente quiere de verdad cuando pide «juntar mis cuentas»: **que sus cosas estén
en una sola**. Eso sí se hace, y **sin tocar ninguna identidad**:

- **Mover el contenido** de la cuenta origen a la cuenta destino.
- **Borrar la de origen, si el dueño quiere.** Opcional y aparte: primero se mueve, después se
  decide.

Reglas (V8):

- **Es local.** Solo se puede hacer donde las dos cuentas ya viven **en la misma máquina**: en
  el aparato entre dos de sus perfiles, o en la bóveda entre dos de los suyos. Nada viaja por
  la red, no hay mensaje nuevo en el protocolo y no hay que emparejar nada.
- **Son dos implementaciones INDEPENDIENTES**, una en el dispositivo y otra en la bóveda. No
  se coordinan, no se llaman entre ellas y ninguna espera a la otra.
- **Es descifrar con la clave de la cuenta origen y volver a cifrar con la de la destino.**
  Por eso solo funciona donde están las dos: hacen falta las dos claves de contenido.
- **Nunca borra el origen por su cuenta.** Copia, verifica, y recién entonces ofrece borrar.

#### Qué se mueve y qué no (la línea es «lo tuyo sí, lo de los demás no»)

| | ¿Se mueve? |
|---|---|
| Tu contenido (documentos, historial, imágenes…) | **Sí.** Es tuyo y vive en tu almacén. |
| **Tu agenda de contactos** (nombres, quién es quién) | **Sí.** El peer book es dato tuyo y está namespaceado por perfil (`dotrino-identity/vault/peerStore.js`), así que viaja con el resto. |
| Las calificaciones que **te dieron** | **No.** Cuelgan del nombre de la cuenta que te las recibió. |
| Las calificaciones que **tú diste** | **No** en el sentido que importa: aunque la agenda se copie, van firmadas con la llave vieja y quedan registradas a nombre de la cuenta vieja. Copiar la lista no las vuelve emitidas por la cuenta nueva. |
| Que **otras personas te tengan guardado** | **No.** Esa entrada está en el aparato de esa persona, con la tarjeta de tu cuenta vieja. Nada de lo que hagas la cambia: si borras el origen, se queda apuntando a una cuenta que ya no existe y tiene que agregarte de nuevo. |

Regla para no equivocarse al escribir la copy: **se mueve lo que guardaste tú; no se mueve lo
que guardaron o dijeron otros**, en ninguna de las dos direcciones. Mover contenido resuelve
«mis cosas en un solo lugar»; no resuelve —ni promete— «mi reputación en un solo lugar».

**Qué decir en la UI** (lenguaje llano, sin jerga):

> Tus dos cuentas siguen siendo dos. Puedes pasar tus cosas —lo que guardaste y tu lista de
> contactos— de una a la otra y luego borrar la que ya no uses. Lo que no se pasa es lo que
> hicieron otras personas: las calificaciones que te dieron se quedan con la cuenta donde te
> las dieron, y quien te tenga guardado en su aparato tendrá que agregarte de nuevo.

### 4.3 Orden: esto es la fase 2

**La fase 1 es el emparejamiento** (§2 y §3): los dos caminos, el `intent`, el perfil que nace
vacío en la bóveda y el que se crea en el aparato. **Mover contenido entre cuentas va después**
y no bloquea nada: son gestos distintos, en pantallas distintas, y el emparejamiento funciona
completo sin ellos.

> ⚠️ Nada de esto deroga la pasada pendiente de `acta-de-perfil.md §7`, que es otra cosa: cómo
> se reconcilia el contenido **entre los aparatos de UNA misma cuenta** cuando editaron lo
> mismo por separado. Eso sigue abierto.

---

## 5. FASE 1 — qué hay que cambiar en el código (el emparejamiento)

### 5.1 ✅ HECHO (2026-07-27) — el camino B ya no pisa la cuenta abierta

> Implementado en `@dotrino/identity@0.34.0`, con la consola y `profile.dotrino.com` al día.
> Lo que sigue queda como registro de qué se arregló y por qué.

`joinProfile` aceptaba cambiar de perfil con que este dispositivo fuera **el único miembro**
del suyo, y entonces hacía `saveActa(candidate)` **encima** del acta que había. O sea:
emparejar un teléfono que ya tenía su cuenta con una bóveda que tiene otra **reemplazaba la
cuenta del teléfono sin preguntar**.

Qué daño hacía, medido y sin exagerar:

- **Activo, hoy.** El contenido del store se namespacea por el **id local del perfil**
  (`store/store.js`, `threads.<pid>.v1`), no por el `profileId` del acta. Así que el contenido
  no se mueve: se queda donde estaba y **pasa a colgar de la cuenta nueva**. Es exactamente la
  fusión de cuentas que §4 prohíbe, hecha en silencio y en una sola dirección.
- **Latente.** El llavero (`keyring`) vive **dentro** del acta y `myCek()` (`:416`) lo lee de
  la vigente. Al sobrescribirla las generaciones se van con ella —`joinProfile` ni siquiera
  las manda al historial—, así que **lo que estuviera cifrado con esa clave quedaría sin
  llave**. Todavía no muerde porque `sealContent`/`openContent` existen en identity y en el
  vault pero **ningún cliente del store los usa aún**; muerde el día que se usen.

**La corrección:**

- [x] **`joinProfile` nunca sobrescribe.** Solo procede sobre un perfil **apto para adoptar**;
      en cualquier otro caso devuelve el conflicto (`perfil-con-datos`, con `profileId`, `seq`
      y número de miembros) y **no escribe nada**.
- [x] **Apto = marcado a propósito, y nada más.** `createProfile({ name, forVault: true })`
      deja `pendingJoin: true` en el registro, y `joinProfile` **exige esa marca**, que se
      limpia al unirse. Sin heurísticas de «parece vacío» y sin camino alternativo: si un
      perfil no nació para adoptar, no adopta. (Dotrino está en pruebas: no hay perfiles
      previos que acomodar, así que la regla puede ser la estricta desde el primer día.)
- [x] **El contenido del store no lo puede comprobar identity** (vive en otro origen): lo
      comprueba **quien llama** (la consola) y, si hay algo, no ofrece el camino B sobre ese
      perfil sino crear uno nuevo. Que identity no pueda verlo es la razón de la marca.
- [x] **`pushHistory(current)` antes de cualquier `saveActa` de adopción**, para que el
      llavero anterior no se evapore ni siquiera en los casos raros.
- [x] `vaultPair` (`:1262`) deja de llamar a `joinProfile` a ciegas (`:1278`): si el perfil
      abierto no es apto, **falla con un mensaje claro** en vez de tragarse la cuenta. Lo mismo
      en el receptor de actas (`:1349`).
- [x] Copy del error, en llano: «Este aparato ya está usando una cuenta. Para usar también la
      de tu computadora, crea una cuenta nueva aquí — la que tienes abierta no se toca.»

**Pruebas (van antes que el arreglo, porque hoy fallan):**

- [x] Teléfono con cuenta y contenido + bóveda con otra cuenta ⇒ la cuenta del teléfono
      **sigue intacta**, con su `profileId`, su acta y su contenido, y aparece una segunda.
- [x] Perfil creado con `forVault: true` ⇒ se une sin fricción y la marca queda limpia.
- [x] Perfil **sin la marca**, aunque parezca vacío ⇒ `perfil-con-datos` y **cero escrituras**
      (comprobar que el acta guardada es byte-idéntica a la de antes).
- [x] Adoptar guarda la anterior en el historial (`actaHistory` la devuelve).

### 5.2 Protocolo: la intención viaja firmada (V7)

- [ ] `intent: 'join' | 'adopt'` dentro del `data` firmado del `ENROLL`
      (`dotrino-identity/vault/remote.js:83`). Sin `intent` ⇒ se trata como `join` **solo si
      el perfil de origen está vacío**; si no, error claro (nunca adivinar).
- [ ] Mensaje nuevo `vault.enroll.adopt`: la bóveda responde `{ pub, encPub, label, code }`
      en vez del cert. El teléfono lo acepta **solo si el código coincide con el suyo**
      (misma defensa que ya tiene el `ENROLLED`, en el otro sentido).
- [ ] Mensaje nuevo `vault.acta.sealed`: el teléfono devuelve el acta con `admit` + `wrap` +
      `handover` en un `seq`.
- [ ] La bóveda, al recibirla: comprobar que **ella** es el `sealer`, guardar en el perfil
      nuevo, re-emitir los certs de todos (D9) y devolver el acta resultante.

### 5.3 Bóveda: perfiles que nacen vacíos

- [ ] `profiles.add(name, { adopt: true })` → un perfil **sin acta propia**, en espera de
      adoptar una. Hoy todo perfil nuevo se crea su génesis y se declara su propia cuenta, y
      entonces adoptar la del teléfono sería «otro perfil» y se rechazaría.
- [ ] `startVault` tolera el perfil vacío (no sirve, no firma, no acepta enroll `join`) y sale
      de ese estado al adoptar.
- [ ] La CLI y `state.json` muestran el **`profileId`**, no la pubkey de la bóveda: desde el
      camino A dejan de ser la misma cosa (la llave de la bóveda es un miembro más).
- [ ] `dotrino-vault profile ls` marca los perfiles adoptados y quién sella cada uno.

### 5.4 Dispositivo: el camino B crea, no reemplaza

- [ ] El flujo de emparejar de la consola crea **primero** el perfil nuevo y enrola con **su**
      llave (hoy enrola con la llave del perfil abierto, `core.js:1262`).
- [ ] El certificado de continuidad se manda **solo** si esa llave tenía vida propia (contenido
      o contactos); una llave recién creada no lo necesita (`core.js:1271`).
- [ ] Al terminar, cambiar al perfil nuevo (con recarga, como todo cambio de perfil).

### 5.5 La pregunta, en la UI

- [ ] Cuando los dos lados tienen cuenta, la consola pregunta **una sola cosa**, con las dos
      consecuencias escritas: *¿de qué cuenta estamos hablando?*
      - «La de este aparato» → camino A (la bóveda la guarda; el aparato deja de sellar).
      - «La de la computadora» → camino B (aquí aparece una cuenta más; la que usabas no se
        toca).
- [ ] En ningún lado se ofrece juntarlas, y si alguien lo busca, sale el texto de §4.
- [ ] `data-testid` en las dos opciones (E2E, CONVENCIONES §5).

### 5.6 Pruebas (`dotrino-test/smoke/`)

- [ ] **A** · teléfono con cuenta + contenido → adopta la bóveda: mismo `profileId`, la bóveda
      queda de `sealer`, el teléfono sigue leyendo su contenido, la bóveda también.
- [ ] **A** · el teléfono **no** es master ⇒ `no-eres-el-master`, y no se sella nada.
- [ ] **A** · código equivocado en el paso 4 ⇒ **no** se traspasa el master (simétrico al que
      ya existe para el cert).
- [ ] **B** · teléfono con cuenta → se une a la de la bóveda: quedan **dos** perfiles, el
      primero intacto y con su contenido legible.
- [ ] **B** · teléfono sin ninguna cuenta ⇒ igual, sin caso especial.
- [ ] Regresión de §5.1 (la que hoy fallaría).

---

## 5bis. FASE 2 — mover contenido entre cuentas (después, y sin bloquear la fase 1)

Dos implementaciones **independientes** (V8), una a cada lado, que **no se hablan**. Misma
idea, distinto almacén.

**En el dispositivo** (`@dotrino/identity` + `@dotrino/store`):

- [ ] `moveContent({ from, to })` entre dos perfiles **de este dispositivo**: abre cada ítem
      con la CEK del perfil origen y lo vuelve a cifrar con la del destino.
- [ ] **Incluye el peer book** (`peerStore.js`, `peers.<pid>.v1`): la agenda es dato del
      usuario y se mueve con el resto. Los **nombres y pubkeys** se copian; las
      **calificaciones emitidas** por la cuenta vieja no se re-atribuyen a la nueva (van
      firmadas por la llave vieja) — se copian como referencia o se dejan, pero nunca se
      presentan como emitidas por la cuenta destino.
- [ ] Requiere tener **las dos claves de contenido**: solo procede si las dos cuentas están
      en este aparato y ninguna está bloqueada.
- [ ] **Copiar → verificar → recién entonces ofrecer borrar** el origen. Nunca en un solo
      paso, nunca automático.
- [ ] Reanudable e **idempotente**: repetir el movimiento no duplica lo ya movido.
- [ ] Choques de identificador: entra igual, con marca de procedencia. **No se pisa nada** y
      no decide ningún reloj.
- [ ] Pantalla en `profile.dotrino.com` con la advertencia de §4.2 (lo que no se mueve).

**En la bóveda** (`dotrino-vault`):

- [ ] Lo mismo entre dos perfiles del daemon (`profiles.json`), por CLI:
      `dotrino-vault content move --from <perfil> --to <perfil>`, con `--dry-run`.
- [ ] Los dos perfiles **desbloqueados** (el candado de `profiles.js` aplica).
- [ ] Registro en el `activity.log` de los dos perfiles: qué se movió y cuándo.
- [ ] Borrar el origen sigue siendo `profile rm`, que ya existe y ya avisa que es irreversible.

**Pruebas:**

- [ ] Mover con contenido cifrado en las dos puntas y comprobar que el destino lo lee y el
      origen **queda intacto** hasta que se borre a propósito.
- [ ] Cortar a la mitad y reanudar: no se duplica ni se pierde nada.
- [ ] Intentarlo con una cuenta que no vive en esta máquina ⇒ error claro, sin tocar nada.

---

## 6. Casos límite

| Situación | Qué pasa |
|---|---|
| El aparato no tiene ninguna cuenta | Camino B, sin preguntar nada: no hay conflicto que resolver. |
| La cuenta del aparato ya vive en otra bóveda | Camino A **no** procede desde el aparato (no es el master). Se traspasa desde la bóveda que manda. |
| La bóveda no tiene ninguna cuenta todavía | Camino A directo: el perfil nace adoptado. |
| Dos cuentas con el mismo nombre visible | Se permite: el nombre es una etiqueta, no la identidad. La UI desempata con la huella (`AB12-CD34`) y el avatar. |
| Se corta la copia de contenido del camino A | El acta ya se traspasó (es instantáneo); la copia se reanuda. Nunca se borra el origen hasta que termina. |
| La bóveda muere después del camino A | Aplica D6: se perdió la cuenta. Por eso la copy insiste en sellar **antes** de apagar nada. |

---

## 7. Lo que NO cambia

El acta, el master único, las capacidades, el CN, la CEK, el emparejamiento endurecido y el
certificado de continuidad se quedan como están. Esto es una decisión sobre **qué se le
pregunta al usuario y qué se hace con su respuesta**, no un modelo nuevo.
