# Acta de perfil — plan de implementación

> Estado: **plan aprobado, sin implementar**. Fecha: 2026-07-25.
> Reemplaza el modelo mental de «una clave maestra con dispositivos delegados» por
> **«un perfil es un conjunto de llaves ligadas por certificados, con un acta firmada
> por UN solo sellador que dice quién puede hacer qué»**.
> Complementa a [`pairing-protocol.md`](./pairing-protocol.md), que sigue vigente: el
> emparejamiento endurecido es el gesto con el que el master admite un miembro.

---

## 0. Qué se decidió y qué se descartó

### 0.1 El problema que resuelve

El usuario necesita **gestionar dónde vive su perfil** —qué dispositivos son suyos,
cuál firma, cuál guarda el contenido— sin que ninguna llave privada viaje nunca.

### 0.2 Decisiones fijadas

| # | Decisión |
|---|---|
| D1 | **Las llaves privadas son intransferibles.** No se copian, no se mueven, no se exportan. Nacen y mueren en su dispositivo. |
| D2 | **El perfil es un acta**: un conjunto de llaves miembro + una política de capacidades, firmada y auto-verificable. |
| D3 | **`profileId` = pubkey de la llave génesis**, y es el nombre **estable** del perfil para siempre. Como toda identidad actual nació en un dispositivo, el `profileId` de cada usuario existente **es su pubkey de siempre** → cero migración de reputación, contactos ni contenido firmado. |
| D4 | **UN SOLO SELLADOR (el «master»).** El acta la sella un único dispositivo. Nunca dos. Por eso **no existen las bifurcaciones**: no se resuelven, son imposibles (ver §2.4). |
| D5 | **La intención es que el master sea el vault.** Un dispositivo nace master (es su propia génesis) y **le cede el master al vault**; de ahí en adelante sólo el vault sella. |
| D6 | **Si se pierde el master, se pierde la cuenta.** Decidido explícitamente por el dueño (2026-07-25), y **no hay mecanismo de recuperación**: sin relevo, sin sucesión, sin miembro de papel. Es una consecuencia asumida de D1, no una carencia a tapar. |
| D7 | **Capacidades: `sign` · `store` · `read`.** Nada más. `admit` y `policy` no existen como capacidades porque **son el master** (cambiar el acta y admitir miembros es sellar). Se mapean 1:1 a los scopes que ya existen (`vault:sign`, `vault:read`, `vault:store`). |
| D8 | **Capacidad efectiva = `cert ∩ acta`.** El cert es la credencial (lo que ya verifican el proxy y `verifyChain`); el acta es la política encima. Permite migración gradual. |
| D9 | **Cadenas de un solo nivel.** Sólo el master emite certs, así que `verifyChain` sirve tal cual. Al ceder el master, el nuevo **re-emite** los certs de todos los miembros (ya se re-emiten cada 30 días por la renovación). |
| D10 | **Renunciar a una capacidad propia es un registro suelto, unilateral y offline** — no toca el acta, y por eso no contradice D4 (§2.2). Sólo puede quitar, nunca otorgar. |
| D11 | **El acta es un snapshot firmado con `seq` monotónico + hash del anterior**, no un log que se reproduce. Tamaño O(miembros), constante en el tiempo. |

### 0.3 Descartado explícitamente (no reintroducir)

- **Copiar / transferir la llave principal.** Era el plan del 2026-07-25 por la mañana; el
  dueño cambió de criterio: las llaves son intransferibles. Con el acta, «el dispositivo
  entrega la firma al vault» se hace **renunciando a la capacidad**, no borrando la llave
  — y es reversible y verificable por terceros, cosa que borrar no es.
- **Llaves extractables opt-in / semilla de recuperación cifrada.** Contradicen D1.
- **Relevo con fecha, sucesión y miembro de papel.** Se propusieron como red para el punto
  único de fallo del sellador; el dueño los descartó junto con D6.
- **Votación / quórum para cambiar el acta.** Innecesario con un solo sellador.
- **`verifyPath` con atenuación / admisión encadenada.** Innecesario con D9.

---

## 1. Modelo de datos

### 1.1 Capacidades (lista cerrada)

| Capacidad | Scope existente | Qué habilita |
|---|---|---|
| `sign` | `vault:sign` | firmar como la identidad ante terceros (reputación, publicaciones) |
| `store` | `vault:store` | leer y escribir el contenido del perfil |
| `read` | `vault:read` | sólo leer el contenido |

Sellar el acta y admitir miembros **no son capacidades**: son el rol de master, y lo tiene
exactamente un miembro.

### 1.2 El acta

```jsonc
{
  "v": 1,
  "profileId": "<pubkeyId de la génesis>",   // nombre estable, nunca cambia
  "sealer": "<JWK string del master vigente>",
  "seq": 42,                                  // monotónico; nunca retrocede
  "prev": "<sha-256 hex del acta seq-1>",
  "members": [
    {
      "pub": "<JWK string>",       // llave de FIRMA del miembro
      "encPub": "<JWK string>",    // llave ECDH del miembro (para envolverle la CEK)
      "label": "Celular de Santiago",
      "caps": ["store", "read"],
      "addedAt": 1690000000000,
      "cert": { /* cert emitido por el sealer vigente; depth 1 */ }
    }
  ],
  "revoked": [ { "nonce": "…", "until": 1690000000000 } ],  // se poda al vencer
  "renounced": [ { "member": "<pub>", "caps": ["sign"], "ts": 0, "sig": "…" } ],
  "updatedAt": 1690000000000,
  "sig": "<firma del sealer>"
}
```

Tamaños medidos con los certs reales del ecosistema (2026-07-25):
pubkey JWK **158 B** · cert **601 B** · miembro completo **~1 KB** ·
**acta de 5 miembros: 5,7 KB** · acta de 20 miembros: ~23 KB.

### 1.3 Retención del historial

- **Un tercero no necesita historial**: recibe el snapshot actual y verifica firma + `seq`.
- **Un miembro que vuelve necesita una ventana** para comprobar el encadenamiento (si está
  en `seq 5` y le llega la 9, necesita 6-7-8). **Ventana normada: las últimas 50 actas o
  12 meses, lo que sea mayor.** El master es quien las conserva.
- Un miembro apagado más tiempo que la ventana **debe re-admitirse** (pasa otra vez por el
  emparejamiento con aprobación humana — deseable, no un defecto).
- El historial de auditoría legible por el dueño va en el `activity.log` que ya existe y
  ya rota a 1 MB (`dotrino-vault/src/vault.js:82-92`).

---

## 2. Reglas normativas (lo que el código debe hacer cumplir)

### 2.1 Sellado

1. **Sólo el `sealer` del acta vigente puede sellar la siguiente.** Cualquier acta firmada
   por otra llave se descarta sin más.
2. Todo cambio incrementa `seq` en 1 y fija `prev` = hash del acta anterior.
3. **Traspaso de master**: lo sella el master actual, nombrando al nuevo en `sealer`. Es la
   última cosa que sella. El nuevo master re-emite los certs de todos los miembros (D9).
   Cubre los dos casos con el **mismo** mecanismo, sin caso especial: dispositivo → vault
   (D5) y **vault → vault** (mudarse de PC). Ninguna llave se mueve, tampoco al traspasar.
   - **Admitir y traspasar van en el MISMO `seq`**: el nuevo sellador debe ser miembro (con
     su cert) antes de sellar, así que el acta del traspaso agrega el miembro *y* cambia el
     `sealer` de una sola vez. Sin ventana intermedia.
   - **El contenido va aparte** y es la parte lenta: el nuevo master lo jala con su capacidad
     `store` (F4), como copia reanudable. El acta se traspasa al instante.
   - **Regla operativa para el usuario: sella el traspaso ANTES de apagar el vault viejo.**
     Con el sello hecho, el master nuevo ya está vivo y perder el viejo no cuesta nada; si el
     viejo muere antes de sellar, aplica D6. Mitiga el punto único de fallo sin contradecirlo.
4. **Prohibido** sellar un acta que deje el perfil sin ningún miembro con `sign`.
   El código rechaza la operación y explica por qué.

### 2.2 Renuncia (el único cambio que no pasa por el master)

Un miembro puede emitir `{ op:'renounce', member, caps:[…], ts, sig }` firmado por sí mismo.
Como **sólo puede quitar**, cualquier verificador la honra por su cuenta sin riesgo, y no
toca el `seq`. El master la absorbe en `renounced` al sellar la siguiente acta.

Caso que cubre: te roban el dispositivo y querés que deje de firmar **ya**, con el vault
apagado.

### 2.3 Verificación de una acción firmada

```
cert válido           ⟺  cert.iss === acta_vigente.sealer   (depth 1, verifyChain)
capacidad_efectiva     =  cert.scope ∩ acta.members[k].caps  −  renuncias del miembro
```
Se rechaza si el acta que presenta el firmante tiene `seq` **menor** al máximo que el
verificador ya vio para ese `profileId`.

- Cada verificador guarda `maxSeq` por `profileId` conocido (un número por contacto).
- Refuerzo temporal: el tope duro de 30 días de los certs (`MAX_DELEGATION_MS`,
  `dotrino-identity/vault/capabilities.js:29`) hace que una política vieja caduque sola.

### 2.4 Por qué no hay bifurcaciones

Con **un solo sellador** (D4) y **llaves intransferibles** (D1), el sellador no se puede
clonar: dos actas legítimas con el mismo `seq` son **criptográficamente imposibles**, no
un conflicto a resolver. **No hay merge, ni precedencia, ni votación.**

Lo único que queda es que el sellador **se contradiga a sí mismo**: se restaura un respaldo
del PC y vuelve a sellar `seq 5` con otro contenido. Contra eso está el pin de `maxSeq`
(§2.3): los miembros que vieron la 6 rechazan la 5, y el master debe emitir un `seq` mayor
para re-sincronizar.

### 2.4.1 Master obsoleto (se restaura un respaldo anterior al traspaso)

Caso: A era master, traspasó a B en `seq 10`, y después A se restaura de un respaldo de
`seq 9` — no sabe que dejó de serlo y sella su propio `seq 10` nombrándose a sí mismo.
Es la única forma en que aparecen dos actas del mismo `seq` firmadas por quien era sellador.

Se resuelve porque **el acta del traspaso la firmó el propio A**: su firma es la prueba
irrefutable de su propia degradación.

1. **Empate a igual `seq`: gana el acta que cambia el `sealer`.** Determinista, sin relojes,
   y en la misma dirección que ya es segura: entre dos versiones firmadas por la misma llave,
   vale la que **le quita** poder al firmante.
   (Si ambas cambian el `sealer` a destinos distintos, el master está mintiendo activamente:
   desempate por hash menor, pero nada salva de un master hostil — puede expulsar a todos.)
2. **Después del traspaso, A no puede nada más.** Sus actas `seq 11`, `12`… van firmadas por
   quien ya no es el `sealer` y se rechazan de plano. **El daño se acota a un solo `seq`.**
3. **Matiz al pin de `maxSeq`:** debe permitir **reemplazo a igual `seq`** cuando la regla 1
   lo dicta (guardando el hash ganador). Sigue prohibido bajar de `seq`. Sin esto, un miembro
   que ya adoptó la rama de A queda atrapado en ella.
4. **Prevención:** al sellar el traspaso, el master viejo **persiste que dejó de serlo y se
   niega a sellar**. Y **todo master, al arrancar, pide el acta vigente antes de sellar**
   (a los miembros y al otro vault por el proxy); si ya no es el `sealer`, se calla. Cubre el
   caso de restauración siempre que haya alguien más en línea.
5. **Avisar lo descartado:** si A alcanzó a sellar cambios en su rama muerta (admitió un
   dispositivo, cambió capacidades), se pierden. La consola lo dice explícitamente.

### 2.4.2 Oráculo de frescura (OPCIONAL y DIFERIDO): la CABECERA del acta en el proxy

> **Postura del dueño (2026-07-25): opcional y diferido.** El conflicto que resuelve exige
> restaurar un respaldo viejo del vault, cosa poco frecuente. **No se construye todavía y
> nada depende de él.** Cuando se retome, el motivo principal no serán los conflictos sino
> **cerrar la ventana de rollback (R1)**: un dispositivo robado presentando el acta vieja en
> la que aún tenía `sign`, ante alguien que no vio la nueva. Sin oráculo eso queda acotado
> por el tope de 30 días de los certs.


El proxy del ecosistema puede guardar, por perfil, **sólo la cabecera** del acta:

```json
{ "profileId": "…", "seq": 42, "hash": "<sha-256 del acta>", "sealer": "<pub>", "sig": "…" }
```

~250 bytes. **No** la lista de miembros, **no** las etiquetas, **no** las capacidades: el acta
completa es un mapa de cuántos dispositivos tienes, cómo se llaman y cuándo los cambias — dato
del usuario, no va al servidor (`CLAUDE.md`, §SEO/privacidad). El acta completa se sigue
obteniendo del miembro con el que hablas; **la baliza sólo dice si la que te dieron está vieja**.

**Regla 1 — el oráculo sólo puede adelantarte, nunca atrasarte.** Una cabecera puede hacerte
buscar un acta más nueva; jamás aceptar una vieja. Un proxy hostil sólo puede **callarse**
(congelarte, DoS visible): no puede falsificar (la cabecera va firmada por el sellador) ni
hacerte retroceder.

**Regla 2 — una cabecera sin acta verificable es un rumor, no un veredicto.** El servidor no
puede validar un cambio de sellador (no tiene el acta); si aceptara cualquier cabecera con
`seq` mayor, cualquiera que conozca tu `profileId` publicaría una `seq 999` firmada con su
propia llave y te congelaría. Por eso **una cabecera sólo cuenta cuando conseguiste y
verificaste el acta correspondiente**. Así el servidor puede ser tonto (guardar, devolver,
monotonía por `profileId`) y el ataque no hace daño.

**Restricciones de diseño:**

- **Opcional siempre.** Todo funciona sin oráculo, con los residuales ya aceptados. Si se
  vuelve requisito, el perfil deja de ser del usuario y pasa a depender de un servidor.
- **Espejable por cualquiera.** La cabecera va firmada: sirve venga de donde venga. Quien se
  autohospeda usa su proxy. Sin esto sería un punto de centralización.
- **Los canales del proxy NO sirven** para esto (son presencia en memoria con expiración,
  `dotrino-proxy/server.js:21`, no un almacén). Va como tabla nueva en el SQLite que ya
  persiste datos por pubkey (`dotrino-proxy/persistence.js`).

**Qué gana:** la prevención de §2.4.1 pasa de «si hay alguien en línea» a fiable (el master
pregunta antes de sellar); un tercero comprueba frescura sin contactarte; R1 y R5 quedan
acotados a «el proxy no responde».

### 2.5 Punto de confianza inicial

Al admitir un dispositivo nuevo no hay negociación: recibe el acta del master y la **pinea**
junto al `profileId`, igual que hoy pinea `qr.iss` (`dotrino-identity/vault/remote.js:69`).
De ahí en adelante sólo acepta actas selladas por el `sealer` que diga el acta que ya tiene.

---

## 3. Arquitectura — dónde vive cada cosa

| Capa | Dueño | Contenido |
|---|---|---|
| Cripto | `@dotrino/identity/capabilities` | acta (build/verify/hash/apply), `wrap/unwrapContentKey`. **Toda la cripto acá y sólo acá.** |
| Protocolo | `@dotrino/vault/protocol` (`lib/src/protocol.js`) | `MSG` / `SCOPE` — fuente única, ya re-exportada por el daemon |
| Lado bóveda | `@dotrino/vault` `lib/src/` | núcleo puro `{ identity, send, audit }` que consumen daemon, `startDeviceVault` y el vendor del iframe |
| Lado dispositivo | `@dotrino/identity` `vault/core.js` | handlers del acta, expuestos por RPC del iframe |
| **UI** | **`vault.dotrino.com`, y sólo ahí** | consola «dónde vive tu perfil». **Cero cripto en la app** |
| Consumidores | proxy · reputation · store · messenger | resolver `pubkey → profileId` |

Nota: el daemon y el paquete npm **sí comparten** el núcleo (ESM puro sin dependencias en
`lib/src/`): el binario lo embebe al compilar con SEA y el iframe lo vendoriza como ya hace.
Lo de 2026-07-10 («no comparten código») era una observación, no una regla.

---

## 4. Fases

### F0 — Deuda que habilita todo lo demás

No depende de ninguna decisión pendiente. **Se puede empezar ya.**

- [ ] Extraer el núcleo del lado-bóveda a `dotrino-vault/lib/src/enroll.js` (puro, recibe
      `{ identity, send, audit }`): `handleEnroll`, `approve`, `reject`, `emitRevoke`.
- [ ] `dotrino-vault/src/vault.js` pasa a consumirlo (hoy duplica ~120 líneas).
- [ ] `dotrino-vault/lib/src/index.js` (`startDeviceVault`) pasa a consumirlo.
- [ ] Re-vendorizar `dotrino-identity/vault/vendor/vault/index.js` + actualizar `VERSION.txt`.
- [ ] **Cerrar `commitCode`**: el dispositivo manda el compromiso `SHA-256(code‖dpub‖sn)` en
      el ENROLL (`dotrino-identity/vault/remote.js:48`) y el vault **valida el código tipeado
      antes de firmar** (`dotrino-vault/src/vault.js:297-311`). Hoy firma el cert sin
      comprobarlo: la defensa vive sólo en el cliente honesto.
- [ ] **Receptor de `vault.revoked` firmado** en `dotrino-identity/vault/core.js`: verificar
      contra la maestra pineada (`verifyRevoke`, `dotrino-vault/src/client.js:97`) antes de
      cualquier borrado.
- [ ] **Quitar el borrado por texto de error**: `handleVaultError` borra cert+device local
      cuando el mensaje contiene «revoked» (`core.js:264-270`), justo lo que
      `pairing-protocol.md §2.3` prohíbe. Sustituirlo por el receptor firmado.
- [ ] Podar `DELEGATIONS_STORAGE` y `REVOCATIONS_STORAGE`: hoy crecen para siempre
      (renovación mensual = 12 entradas por dispositivo por año, `core.js:756-759`;
      revocaciones nunca podadas, `core.js:254`). Renovar **reemplaza** la entrada; un
      revocado se cae al vencer su cert.
- [ ] Tests: `node --test` verde en identity y vault; test nuevo del `commitCode` (aprobar
      con código equivocado **no** debe emitir cert).
- [ ] Publicar `@dotrino/identity` y `@dotrino/vault` (commit → tag → `npm publish`).

**Hecho cuando:** aprobar con un código incorrecto no emite cert; un `MSG.ERROR` de texto no
borra nada; un `vault.revoked` firmado sí; el emparejamiento vive en un solo módulo; los
registros dejan de crecer sin límite.

---

### F1 — El acta v1 y la consola

- [ ] `buildActa` / `verifyActa` / `actaHash` / `applyChange` en
      `@dotrino/identity/capabilities` (módulo puro: sin kv, sin red).
      **No hacen falta scopes nuevos** (D7) ni `verifyPath` (D9).
- [ ] `dotrino-identity/vault/core.js`: persistencia del acta + handlers `profileActa()`,
      `profileMembers()`, `admitMember()`, `setCaps()`, `removeMember()`, `myMembership()`,
      `isMaster()`.
- [ ] Reglas §2.1 en `applyChange` (sólo sella el `sealer`; `seq`+`prev`; no dejar el perfil
      sin `sign`), con test de cada rechazo.
- [ ] Pin de `maxSeq` por `profileId` en el verificador (§2.3).
- [ ] Migración: al arrancar sin acta, **generar la v1 automáticamente** — un miembro (la
      llave actual), `sealer` = esa misma llave, todas las capacidades. Invisible.
- [ ] `dotrino-identity/src/index.js` + `index.d.ts` + `src/node.js`: wrappers.
- [ ] **Consola en `vault.dotrino.com`**: la landing actual (`web/src/App.vue`) queda como
      home y se agrega `/dispositivos` con: quién es quién, **qué puede hacer cada uno**,
      **quién sella**, admitir y expulsar.
- [ ] Aviso permanente y en lenguaje llano de la consecuencia de D6: «si pierdes este
      dispositivo, pierdes el perfil». Sin prometer una recuperación que no existe.
- [ ] Normalizar esa app: `<dotrino-topbar>` con `profile` (§5/§6.1 de CONVENCIONES),
      `@dotrino/support@0.8` (hoy 0.6.0), bilingüe es/en.
- [ ] Migrar desde `dotrino_profile/src/main.js` las vistas `/vault` (`:336`) y `/myvault`
      (`:653`) — ~500 de sus 893 líneas — y dejar redirect en las rutas viejas.
- [ ] `dotrino-vault/src/ctl.js`: apuntar el QR a `vault.dotrino.com` (hoy `PROFILE_URL`, `:140`).
- [ ] CLI/TUI espejo: `dotrino-vault members`, `caps <deviceId> <±cap>`.

**Hecho cuando:** el usuario ve en `vault.dotrino.com` sus dispositivos, qué puede hacer cada
uno y quién sella; puede admitir y expulsar; y nada del comportamiento actual cambió (el acta
se genera sola y todavía no la consume nadie para decidir).

---

### F2 — Traspaso del master al vault, renuncia y re-enrutamiento de la firma

**Es el corazón del modelo: al terminar F2, funciona lo que el dueño pidió.**

- [ ] **Traspaso**: el master actual sella un acta que, en el **mismo `seq`**, admite al
      nuevo sellador como miembro y lo nombra en `sealer` (§2.1.3). Un solo flujo cubre
      dispositivo → vault y **vault → vault** (mudarse de PC).
- [ ] El nuevo master, al recibirlo, **re-emite los certs de todos los miembros** (D9).
- [ ] Consola: el traspaso avisa **«sella antes de apagar el vault viejo»** y sólo después
      ofrece migrar el contenido (que es reanudable y no crítico).
- [ ] **Master obsoleto** (§2.4.1): al traspasar, el master viejo persiste que dejó de serlo
      y se niega a sellar; todo master pide el acta vigente al arrancar antes de sellar;
      empate a igual `seq` lo gana el acta que cambia el `sealer`; el pin admite reemplazo a
      igual `seq`; la consola avisa qué cambios se descartaron. Con test de cada regla.
- [ ] **Renuncia** (§2.2): botón «Este dispositivo ya no firma por mí» → registro suelto
      firmado, honrado de inmediato aunque el vault esté apagado; el master lo absorbe después.
- [ ] `signData` bifurcado en `dotrino-identity/vault/core.js:738`:
      - con `sign` efectivo → firma local (idéntico a hoy),
      - sin `sign` → re-enruta a `vaultSign` (`core.js:869`, ya implementado de punta a punta
        contra `handleSign`, `dotrino-vault/src/vault.js:135`) y devuelve la pubkey del
        firmante del perfil, **estable**,
      - `op:'identify'` **siempre** firma local (el transporte lo necesita y el proxy ya lo
        acepta: `dotrino-proxy/server.js:1626-1630`),
      - sin miembro con `sign` alcanzable → error explícito `perfil-sin-firmante`, nunca colgarse.
- [ ] Distribución del acta: `vault.devices` (`dotrino-vault/src/vault.js:189`) pasa a servir
      también el acta vigente; los miembros la adoptan si el `sealer` y el `seq` verifican (§2.5).
- [ ] Ventana de retención de actas (§1.3) + re-admisión del que quedó fuera de ventana.
- [ ] Copy en lenguaje llano (§9.1): «Tu bóveda firmará por ti. Si la apagas, este dispositivo
      no podrá firmar hasta que vuelva.»

**Oráculo de frescura (§2.4.2) — opcional, se puede diferir sin bloquear F2:**

- [ ] `dotrino-proxy`: tabla `acta_heads` en `persistence.js` + ops `acta.head.put` /
      `acta.head.get`. El servidor es **tonto**: guarda, devuelve y exige monotonía por
      `profileId`. **No** guarda el acta, sólo la cabecera (~250 B).
- [ ] Cliente: publicar la cabecera al sellar; consultarla al arrancar el master (antes de
      sellar) y al verificar una firma ajena.
- [ ] Regla 1 (sólo adelanta, nunca atrasa) y regla 2 (cabecera sin acta verificada = rumor),
      con test de cada una — incluido el intento de congelar con una `seq` alta ajena.
- [ ] Que funcione con el oráculo apagado, byte-idéntico a no tenerlo.

**Hecho cuando:** el dispositivo le cede el master al vault, le quita `sign` a sí mismo, sigue
funcionando firmando a través del vault, y con el vault apagado da un error claro en vez de
firmar por su cuenta.

---

### F3 — Unir identidades que ya existen

- [ ] **Cert de continuidad**: al unir dos identidades preexistentes, la absorbida firma
      «esta pubkey es ahora miembro de `<profileId>`»; el master lo sella en el acta y queda
      como puente para que su reputación previa siga contando.
- [ ] UX de unión en la consola, con las dos consecuencias dichas en claro.

**Hecho cuando:** dos identidades viejas quedan en un solo perfil sin perder reputación.

---

### F4 — Contenido unificado

- [ ] Clave de contenido del perfil (CEK) **envuelta a la `encPub` de cada miembro** (reusar
      el ECDH+AES-GCM de `core.js:936-955`; **no reimplementar**).
- [ ] Admitir miembro → re-envolver. Expulsar → rotar CEK y re-envolver al resto.
- [ ] Llavero de CEK antiguas para leer contenido viejo (32 B c/u) + re-cifrado perezoso.
- [ ] `@dotrino/store` lee/escribe por perfil, no por dispositivo.

**Hecho cuando:** admitir un dispositivo le da acceso al contenido ya existente, y expulsarlo
le corta el acceso al contenido futuro.

---

### F5 — Consumidores y endurecimiento del vault

- [ ] `dotrino-proxy/server.js`: `verifyDeviceCert` (`:281`) contra el `sealer` vigente.
- [ ] `@dotrino/reputation`: sujeto = `profileId` (compatible: hoy ya **es** la pubkey).
- [ ] `@dotrino/messenger` y contactos: un peer = un perfil con N llaves; cifrar a todos los
      miembros (encaja con `recipients[]` que ya existe).
- [ ] Vault: cifrado en reposo **ligado a la máquina** (`machine-id` + serial de disco + salt
      local 0600, más la contraseña del perfil si está puesta). Copiar `identity.json` a otra
      máquina deja de servir. **No** protege contra root local: decirlo así en la copy.
- [ ] TPM 2.0 opt-in (avanzado; rompe la portabilidad del binario único).

> ⚠️ Con D6 (perder el master = perder la cuenta), el ligado a hardware **sube la apuesta**:
> un cambio de disco o de placa mata el perfil. Va opt-in, con la advertencia explícita.

---

## 5. Residuales aceptados (documentar, no prometer que se resuelven)

- **R1 — Ventana de rollback.** Quien nunca vio el acta nueva puede aceptar una vieja.
  Acotado por el pin de `maxSeq` y el tope de 30 días de los certs.
- **R2 — La política la hacen cumplir los verificadores, no el dispositivo.** Un miembro al
  que le quitaste `sign` sigue teniendo su llave y físicamente puede firmar; lo que ocurre es
  que **los demás dejan de aceptarle esa firma**.
- **R3 — No hay recuperación (por diseño, D6).** Perder el master es perder el perfil. No es
  un pendiente: es la decisión del dueño, y la UI la dice en voz alta en vez de esconderla.
- **R4 — Expulsar no recupera lo ya leído.** Rotar la CEK protege el contenido futuro.
- **R5 — Miembro aislado de la rama buena.** Un miembro que nunca se cruza con la rama del
  master nuevo sigue creyendo que el viejo manda, y éste puede renovarle certs en su rama
  muerta. Inevitable en cualquier sistema que funcione offline: nadie se entera de lo que
  nunca le llegó. Colapsa a la rama buena en cuanto cualquiera de los dos toca la red donde
  está el master vigente.
- **R6 — Dependencia del vault online** cuando es el único con `sign`. Salida futura si
  molesta: tickets de firma de corta vida pre-emitidos. No entra en la primera versión.

## 6. Fuera de alcance

Rotación de identidad (cambiar el `profileId`), federación del registro de revocación, y
tickets de firma offline. Ninguno bloquea las fases de arriba.
