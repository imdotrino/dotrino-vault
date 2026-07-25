# Acta de perfil — plan de implementación

> Estado: **plan aprobado, sin implementar**. Fecha: 2026-07-25.
> Reemplaza el modelo mental de «una clave maestra con dispositivos delegados» por
> **«un perfil es un conjunto de llaves ligadas por certificados, con una política
> firmada que dice quién puede hacer qué»**.
> Complementa a [`pairing-protocol.md`](./pairing-protocol.md) (que sigue vigente:
> el emparejamiento endurecido es el gesto con el que se admite un miembro).

---

## 0. Qué se decidió y qué se descartó

### 0.1 El problema que resuelve

El usuario necesita **gestionar dónde vive su perfil** —qué dispositivos son suyos,
cuál firma, cuál guarda el contenido— sin que ninguna llave privada viaje nunca.

### 0.2 Decisiones fijadas

| # | Decisión |
|---|---|
| D1 | **Las llaves privadas son intransferibles.** No se copian, no se mueven, no se exportan. Nacen y mueren en su dispositivo. |
| D2 | **El perfil es un acta**, no una llave: un conjunto de llaves miembro + una política de capacidades, todo firmado y auto-verificable. |
| D3 | **`profileId` = pubkey de la llave génesis.** Como toda identidad actual nació en un dispositivo, el `profileId` de cada usuario existente **es su pubkey de siempre** → cero migración de reputación, contactos ni contenido firmado. |
| D4 | **Renunciar es unilateral; ampliar requiere `policy`.** Un miembro puede bajarse a sí mismo cualquier capacidad, solo. Otorgar (a sí mismo o a otro) exige la firma de quien tenga `policy`. |
| D5 | **Capacidad efectiva = `cert ∩ acta`.** El cert es la credencial (lo que ya verifican el proxy y `verifyChain`); el acta es la política encima. Permite migración gradual. |
| D6 | **El acta es un snapshot firmado con `seq` monotónico + hash del anterior**, no un log que se reproduce. Tamaño O(miembros), constante en el tiempo. |
| D7 | **`policy` la tienen la génesis y el miembro de papel**, nadie más por defecto. |
| D8 | **Miembro de papel**: llave generada offline, guardada como QR impreso, con `admit` + `policy` y **sin** `sign` ni `read`. Es la red de recuperación del modelo (sin llaves móviles, perder todos los miembros = perder el perfil). |
| D9 | **Reconciliación determinista, sin votación**: gana el `seq` mayor verificable; ante fork, unión restrictiva. Ver §2.4. |

### 0.3 Descartado explícitamente (no reintroducir)

- **Copiar / transferir la llave principal.** Era el plan del 2026-07-25 por la mañana;
  el dueño cambió de criterio: las llaves deben ser intransferibles. Con el acta, «el
  dispositivo entrega la firma al vault» se hace **renunciando a la capacidad**, no
  borrando la llave — y es reversible y verificable por terceros, cosa que borrar no es.
- **Llaves extractables opt-in / semilla de recuperación cifrada.** Contradicen D1.
  La recuperación es el **miembro de papel** (D8), que no es copia de ninguna llave viva.
- **Votación / quórum M-de-N para cambiar el acta.** D4 lo hace innecesario para el caso
  real (renunciar) y D9 resuelve los conflictos sin coordinación.

---

## 1. Modelo de datos

### 1.1 Capacidades (lista cerrada — no crecer sin muy buena razón)

| Capacidad | Qué habilita |
|---|---|
| `sign` | firmar como la identidad ante terceros (reputación, publicaciones, retos) |
| `store` | leer y escribir el contenido del perfil |
| `read` | sólo leer el contenido |
| `admit` | admitir miembros nuevos (emitir certs de membresía) |
| `policy` | cambiar el acta: otorgar capacidades, expulsar miembros |

Las capacidades existentes `vault:sign` / `vault:read` / `vault:store`
(`dotrino-vault/lib/src/protocol.js`) se mapean 1:1 a las tres primeras; `admit` y
`policy` son nuevas.

### 1.2 El acta

```jsonc
{
  "v": 1,
  "profileId": "<pubkeyId de la génesis>",
  "seq": 42,                       // monotónico; nunca retrocede
  "prev": "<sha-256 hex del acta seq-1>",
  "members": [
    {
      "pub": "<JWK string>",       // llave de FIRMA del miembro
      "encPub": "<JWK string>",    // llave ECDH del miembro (para envolverle la CEK)
      "label": "Celular de Santiago",
      "caps": ["store", "read"],   // la política; ver D5
      "addedAt": 1690000000000,
      "cert": { /* cert de membresía, encadenable */ }
    }
  ],
  "revoked": [ { "nonce": "…", "until": 1690000000000 } ],  // se poda al vencer
  "updatedAt": 1690000000000,
  "sig": "<firma del miembro con `policy` que emitió esta versión>"
}
```

Tamaños medidos con los certs reales del ecosistema (2026-07-25):
pubkey JWK **158 B** · cert **601 B** · miembro completo **~1 KB** ·
**acta de 5 miembros: 5,7 KB** · acta de 20 miembros: ~23 KB.

### 1.3 Retención del historial

- **Un tercero no necesita historial**: recibe el snapshot actual y verifica firma + `seq`.
- **Entre miembros del mismo perfil sí hace falta una ventana** para poder comprobar el
  encadenamiento al reconciliar (si estoy en `seq 5` y me llega la 9, necesito 6-7-8).
  **Ventana normada: las últimas 50 actas o 12 meses, lo que sea mayor.**
- Un miembro apagado más tiempo que la ventana **no valida el salto y debe re-admitirse**
  (pasa otra vez por el emparejamiento con aprobación humana — deseable, no un defecto).
- El historial de auditoría legible por el dueño va en el `activity.log` que ya existe
  y ya rota a 1 MB (`dotrino-vault/src/vault.js:82-92`).

---

## 2. Reglas normativas (lo que el código debe hacer cumplir)

### 2.1 Cambio de política

1. Un miembro puede **quitarse a sí mismo** capacidades sin firma de nadie más (D4).
2. **Otorgar** cualquier capacidad, a quien sea, exige firma de un miembro con `policy`.
3. **Prohibido** aplicar un cambio que deje el perfil **sin ningún miembro vivo con `sign`**
   o **sin ningún miembro con `policy`**. El código rechaza la operación y explica por qué.
4. Todo cambio incrementa `seq` en 1 y fija `prev` = hash del acta anterior.

### 2.2 Verificación de una acción firmada

```
capacidad_efectiva = cert.scope ∩ acta.members[k].caps
```
Se rechaza si el acta que presenta el firmante tiene `seq` **menor** al máximo que el
verificador ya vio para ese `profileId` (anti-rollback, ver 2.3).

### 2.3 Anti-rollback

- Cada verificador guarda `maxSeq` por `profileId` conocido (un número por contacto).
- **Nunca se acepta un `seq` menor al ya visto.**
- Refuerzo temporal: el tope duro de 30 días de los certs (`MAX_DELEGATION_MS`,
  `dotrino-identity/vault/capabilities.js:29`) hace que una política vieja caduque sola.
- **Residual aceptado:** un verificador que nunca vio el acta nueva puede aceptar una
  vieja. Es el mismo residual que ya tiene la revocación; no se inventa uno nuevo.

### 2.4 Reconciliación entre miembros

Al conectarse, cada uno anuncia `{ profileId, seq, hash }`. El que está atrás pide la
más nueva y **la adopta sólo si**: (a) la firma es de un miembro que tenía `policy` en
el acta que él ya tenía, (b) el `prev` encadena, (c) el `seq` es mayor. Si algo falla,
**no adopta y conserva la suya**.

**Fork** (dos actas con el mismo `seq` y distinto hash), en este orden:

1. Si **ambos cambios sólo QUITAN** capacidades → **se fusionan** aplicando los dos
   (intersección). Determinista y nunca otorga nada que ninguno otorgaba.
2. Si alguno **OTORGA** → no se fusiona: gana el firmado por el `policy` de mayor
   precedencia (génesis > resto); el otro se descarta y **se avisa al usuario qué se perdió**.
3. **Nunca «gana el más nuevo por fecha»**: los relojes son manipulables desde el dispositivo.

### 2.5 Punto de confianza inicial

Al admitir un dispositivo nuevo no hay negociación: recibe el acta del que lo admite y
la **pinea** junto al `profileId`, igual que hoy pinea `qr.iss`
(`dotrino-identity/vault/remote.js:69`). De ahí en adelante sólo acepta actas que encadenen.

---

## 3. Arquitectura — dónde vive cada cosa

Regla dura, para no duplicar (hoy el «lado bóveda» está escrito **tres veces**: daemon,
lib y el vendor del iframe):

| Capa | Dueño | Contenido |
|---|---|---|
| Cripto | `@dotrino/identity/capabilities` | `verifyPath`, acta, `wrap/unwrapContentKey`. **Toda la cripto acá y sólo acá.** |
| Protocolo | `@dotrino/vault/protocol` (`lib/src/protocol.js`) | `MSG` / `SCOPE` — fuente única, ya re-exportada por el daemon |
| Lado bóveda | `@dotrino/vault` `lib/src/` | núcleo puro `{ identity, send, audit }` que consumen daemon, `startDeviceVault` y el vendor |
| Lado dispositivo | `@dotrino/identity` `vault/core.js` | handlers del acta, expuestos por RPC del iframe |
| **UI** | **`vault.dotrino.com`, y sólo ahí** | consola «dónde vive tu perfil». **Cero cripto en la app** |
| Consumidores | proxy · reputation · store · messenger | resolver `pubkey → profileId` |

---

## 4. Fases

### F0 — Deuda que habilita todo lo demás

No depende de ninguna decisión pendiente. **Se puede empezar ya.**

> ⚠️ **Punto abierto (decisión del dueño, pendiente).** El 2026-07-10 el dueño decidió
> explícitamente que **el daemon y el paquete npm `@dotrino/vault` conviven SIN compartir
> código** («no es necesario que compartan código»). Las tres primeras casillas de abajo
> van en contra de esa decisión. Con el acta, el lado-bóveda deja de ser sólo el enroll y
> pasa a incluir política, reconciliación y forks — mantener eso escrito tres veces
> (daemon, lib, vendor) es donde veo el mayor riesgo de que diverjan en silencio.
> **Si el dueño ratifica la decisión de 2026-07-10, se saltan esas tres casillas** y cada
> lado implementa lo suyo; el resto de F0 no cambia.

- [ ] Extraer el núcleo del lado-bóveda a `dotrino-vault/lib/src/enroll.js` (puro,
      recibe `{ identity, send, audit }`): `handleEnroll`, `approve`, `reject`, `emitRevoke`.
- [ ] `dotrino-vault/src/vault.js` pasa a consumirlo (hoy duplica ~120 líneas).
- [ ] `dotrino-vault/lib/src/index.js` (`startDeviceVault`) pasa a consumirlo.
- [ ] Re-vendorizar `dotrino-identity/vault/vendor/vault/index.js` + actualizar su `VERSION.txt`.
- [ ] **Cerrar `commitCode`**: el dispositivo manda el compromiso `SHA-256(code‖dpub‖sn)`
      en el ENROLL (`dotrino-identity/vault/remote.js:48`) y el vault **valida el código
      tipeado antes de firmar** (`dotrino-vault/src/vault.js:297-311`).
      Hoy firma el cert sin comprobarlo: la defensa vive sólo en el cliente honesto.
- [ ] **Receptor de `vault.revoked` firmado** en `dotrino-identity/vault/core.js`:
      verificar contra la maestra pineada (`verifyRevoke`, `dotrino-vault/src/client.js:97`)
      antes de cualquier borrado.
- [ ] **Quitar el borrado por texto de error**: `handleVaultError` borra cert+device local
      cuando el mensaje contiene «revoked» (`core.js:264-270`), justo lo que
      `pairing-protocol.md §2.3` prohíbe. Sustituirlo por el receptor firmado.
- [ ] Podar `DELEGATIONS_STORAGE` y `REVOCATIONS_STORAGE`: hoy crecen para siempre
      (renovación mensual = 12 entradas por dispositivo por año, `core.js:756-759`;
      revocaciones nunca podadas, `core.js:254`). Renovar **reemplaza** la entrada;
      un revocado se cae al vencer su cert.
- [ ] Tests: `node --test` en identity y vault siguen verdes; test nuevo del `commitCode`
      (aprobar con código equivocado **no** debe emitir cert).
- [ ] Publicar `@dotrino/identity` y `@dotrino/vault` (commit → tag → `npm publish`).

**Hecho cuando:** aprobar con un código incorrecto no emite cert; un `MSG.ERROR` de texto
no borra nada; un `vault.revoked` firmado sí; el flujo de emparejamiento vive en un solo
módulo; los registros dejan de crecer sin límite.

---

### F1 — El acta v1 (membresía + capacidades) y la consola

- [ ] `@dotrino/identity/capabilities`: `SCOPE.ADMIT = 'profile:admit'`,
      `SCOPE.POLICY = 'profile:policy'`.
- [ ] `verifyPath({ chain, leaf, profileId, expectedCap, revoked, now })`: cadena de N
      certs con **atenuación** (`scope ⊆` del padre, `exp ≤` del padre, `iss(n) = sub(n-1)`),
      raíz = `profileId`. `verifyChain` actual queda como el caso N=1 (no se rompe).
- [ ] `buildActa` / `verifyActa` / `actaHash` / `applyChange` (módulo puro, sin kv ni red).
- [ ] `dotrino-identity/vault/core.js`: persistencia del acta + handlers
      `profileActa()`, `profileMembers()`, `admitMember()`, `setCaps()`, `removeMember()`,
      `myMembership()`.
- [ ] Reglas §2.1 aplicadas en `applyChange` (incluido «no dejar el perfil sin `sign`
      ni sin `policy`»), con tests de cada rechazo.
- [ ] Migración: al arrancar sin acta, **generar la v1 automáticamente** con un solo
      miembro (la llave actual) y todas las capacidades. Invisible para el usuario.
- [ ] `dotrino-identity/src/index.js` + `index.d.ts` + `src/node.js`: wrappers.
- [ ] **Miembro de papel**: generar llave offline → acta con `admit` + `policy` →
      render QR imprimible (reusar `dotrino-vault/src/qr.js` / el generador del cliente).
      Nunca se persiste su privada en ningún dispositivo.
- [ ] **Consola en `vault.dotrino.com`**: la landing actual (`web/src/App.vue`) se queda
      como home y se agrega `/dispositivos` con: quién es quién, **qué puede hacer cada
      uno**, admitir, expulsar, y el aviso «tienes un solo miembro» mientras aplique.
- [ ] Normalizar esa app: `<dotrino-topbar>` con `profile` (§5/§6.1 de CONVENCIONES),
      `@dotrino/support@0.8` (hoy tiene 0.6.0), bilingüe es/en.
- [ ] Migrar desde `dotrino_profile/src/main.js` las vistas `/vault` (`:336`) y
      `/myvault` (`:653`) — ~500 de sus 893 líneas — y dejar redirect en las rutas viejas.
- [ ] `dotrino-vault/src/ctl.js`: apuntar el QR a `vault.dotrino.com` (hoy `PROFILE_URL`, `:140`).
- [ ] CLI/TUI espejo: `dotrino-vault members`, `caps <deviceId> <±cap>`.

**Hecho cuando:** el usuario ve en `vault.dotrino.com` sus dispositivos y qué puede hacer
cada uno; puede admitir y expulsar; existe el miembro de papel; nada del comportamiento
actual cambió (el acta se genera sola y todavía no la consume nadie para decidir).

---

### F2 — Renuncia y re-enrutamiento de la firma  ← **acá el modelo ya funciona**

- [ ] Botón **«Este dispositivo ya no firma por mí»** en la consola: quita `sign` de sus
      propias `caps` (unilateral, D4) y publica `seq+1`.
- [ ] `signData` bifurcado en `dotrino-identity/vault/core.js:738`:
      - con `sign` en el acta → firma local (idéntico a hoy),
      - sin `sign` → re-enruta a `vaultSign` (`core.js:869`, ya implementado de punta a
        punta contra `handleSign`, `dotrino-vault/src/vault.js:135`) y devuelve la
        pubkey del firmante del perfil, **estable**,
      - `op:'identify'` **siempre** firma local (el transporte lo necesita, y el proxy ya
        lo acepta: `dotrino-proxy/server.js:1626-1630`),
      - sin miembro con `sign` alcanzable → error explícito `perfil-sin-firmante`,
        nunca colgarse.
- [ ] Reconciliación §2.4 entre miembros (anuncio `{seq,hash}` + adopción + fork).
- [ ] Ventana de retención de actas (§1.3) + re-admisión del que quedó fuera de ventana.
- [ ] `vault.devices` (`dotrino-vault/src/vault.js:189`) pasa a servir también el acta actual.
- [ ] Copy en lenguaje llano (§9.1): «Tu bóveda firmará por ti. Si la apagas, este
      dispositivo no podrá firmar hasta que vuelva.»

**Hecho cuando:** quitas `sign` al celular, el celular sigue funcionando firmando a través
del vault, y con el vault apagado da un error claro en vez de firmar por su cuenta.

---

### F3 — Admisión encadenada y unión de identidades existentes

- [ ] Un miembro con `admit` puede admitir a otro (hoy sólo la raíz emite: `iss` forzado
      a la propia en `core.js:756`). Cadenas de 2+ eslabones validadas con `verifyPath`.
- [ ] **Cert de continuidad**: al unir dos identidades que ya existían, la absorbida firma
      «esta pubkey es ahora miembro de `<profileId>`»; queda en el acta como puente para
      que su reputación previa siga contando.
- [ ] UX de unión en la consola, con las dos consecuencias dichas en claro.

**Hecho cuando:** un celular admitido por el vault puede admitir la laptop sin que el
génesis intervenga; dos identidades viejas se unen sin perder reputación.

---

### F4 — Contenido unificado

- [ ] Clave de contenido del perfil (CEK) **envuelta a la `encPub` de cada miembro**
      (reusar el ECDH+AES-GCM de `core.js:936-955`; **no reimplementar**).
- [ ] Admitir miembro → re-envolver. Expulsar → rotar CEK y re-envolver al resto.
- [ ] Llavero de CEK antiguas para leer contenido viejo (32 B c/u) + re-cifrado perezoso.
- [ ] `@dotrino/store` lee/escribe por perfil, no por dispositivo.

**Hecho cuando:** admitir un dispositivo le da acceso al contenido ya existente, y
expulsarlo le corta el acceso al contenido futuro.

---

### F5 — Consumidores y endurecimiento del vault

- [ ] `dotrino-proxy/server.js`: `verifyDeviceCert` (`:281`) generalizado a cadena.
- [ ] `@dotrino/reputation`: sujeto = `profileId` (compatible: hoy ya **es** la pubkey).
- [ ] `@dotrino/messenger` y contactos: un peer = un perfil con N llaves; cifrar a todos
      los miembros (encaja con `recipients[]` que ya existe).
- [ ] Vault: cifrado en reposo **ligado a la máquina** (`machine-id` + serial de disco +
      salt local 0600, más la contraseña del perfil si está puesta). Copiar
      `identity.json` a otra máquina deja de servir. **No** protege contra root local:
      decirlo así en la copy, sin prometer de más.
- [ ] TPM 2.0 opt-in (avanzado; rompe la portabilidad del binario único).
- [ ] **Requisito bloqueante del punto anterior**: no permitir activar el ligado a
      hardware si el perfil no tiene otro miembro con `admit` — un cambio de disco o
      placa deja ese miembro inutilizable para siempre.

---

## 5. Residuales aceptados (documentar, no prometer que se resuelven)

- **R1 — Ventana de rollback.** Quien nunca vio el acta nueva puede aceptar una vieja.
  Acotado por el pin de `maxSeq` y el tope de 30 días de los certs.
- **R2 — La política la hacen cumplir los verificadores, no el dispositivo.** Un miembro
  al que le quitaste `sign` sigue teniendo su llave y físicamente puede firmar; lo que
  ocurre es que **los demás dejan de aceptarle esa firma**.
- **R3 — Sin llaves móviles no hay respaldo.** Perder todos los miembros = perder el
  perfil, sin excepción. Por eso el miembro de papel es parte de F1, no un extra.
- **R4 — Expulsar no recupera lo ya leído.** Rotar la CEK protege el contenido futuro.
- **R5 — Dependencia del vault online** cuando es el único con `sign`. Salida futura si
  molesta: tickets de firma de corta vida pre-emitidos. No entra en la primera versión.

## 6. Fuera de alcance

Rotación de identidad (cambiar el `profileId`), federación del registro de revocación,
y tickets de firma offline. Ninguno bloquea las fases de arriba.
