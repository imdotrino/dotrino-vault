All critical facts confirmed. The proxy `handleIdentifyMessage` (server.js:1496-1548) verifies the signature against the literal `data.publickey` JWK and `bindPubkey(data.publickey, ws.token)` — so delegated identify under D is structurally possible (D identifies as D), but the master's offline queue is keyed by master pubkey. The vault replies by `from` token (vault.js:60-61), and the daemon store is a folder/children tree (no threads). I have enough to write the decision.

I'll write the document directly as my output (per instructions, no .md file).

---

# Decisión de arquitectura: el vault de PC como store + identidad centralizada del usuario

## 1. Veredicto y modelo elegido

**Modelo elegido: "dispositivo delegado por origin compartido", construido sobre la cripto de capacidades que ya existe (`makeDeviceKey` / `signDelegation` / `verifyChain`, cert con tope 30 días y revocable), con el daemon de PC como autoridad maestra y el proxy del ecosistema como único transporte.** El cert delegado (D←P) y la llave privada de dispositivo `D` viven **dentro del iframe del origin compartido correspondiente a cada pilar**: el de identidad en `id.dotrino.com` (para firmar), y un cert hermano **independiente** en `store.dotrino.com` (para el store). No se centraliza la llave de dispositivo en un solo origin que sirva a los dos pilares, porque `id.` y `store.` son orígenes distintos (CNAMEs distintos) y **no comparten storage** — el "canal entre iframes hermanos" que proponían las lentes 1 y 2 es frágil y no está especificado, así que se descarta: **cada pilar enrola su propio dispositivo** contra el mismo vault maestro (dos certs, mismo `iss`, scopes distintos). Todo es **estrictamente opt-in**: sin pairing, `signData` firma con la maestra local del iframe (como hoy) y el store sirve desde IndexedDB+Drive (como hoy), byte-idéntico. Quien no empareja no ve ningún cambio, y ninguna app del ecosistema necesita re-desplegarse porque la API `postMessage` de `@dotrino/identity` y `@dotrino/store` no cambia (los métodos `vault*` son aditivos).

**Lo que las críticas mataron y aquí se corrige o descarta:**

- **La identidad NO se "unifica" moviendo el store.** Verificado en `dotrino-identity/vault/core.js:23,461-465`: `id.dotrino.com` ya custodia una maestra en el navegador (`KEY_STORAGE`) con la que TODAS las apps firman hoy, y el QR del daemon trae `iss = masterPubkeyOf(daemon)`, que es **otra** clave. Por tanto, el objetivo "tu identidad sale de tu máquina" se logra **re-enrutando las firmas a la maestra del daemon vía cert delegado**, no asumiendo que ambas maestras son la misma. La maestra del navegador queda como identidad legacy/respaldo y NO se borra al emparejar (revertir es sin pérdida de la llave; ver §6 el caveat del rastro firmado).
- **`signData` NO tendrá retorno polimórfico silencioso.** Las críticas mostraron que devolver a veces `publickey=D` y a veces `publickey=master` rompe a los consumidores que asumen `publickey == identidad estable` (messenger usa `id.me.publickey` como threadKey/direccionamiento; reputation lo usa como subject — `core.js:356,376`). **Decisión: en modo delegado, `signData` por defecto re-enruta a la maestra del daemon y devuelve `publickey = master-del-daemon` (estable).** La firma local con `D` solo se usa para el **transporte** (identify del proxy), nunca para identidad/reputación de cara a otras personas.
- **El proxy NO entiende cadenas de delegación** (`server.js:1496-1548`: verifica la firma contra el JWK literal de `data.publickey`). Decisión: el iframe se identifica al proxy **como D** (firma D, `publickey=D` — válido para el proxy tal cual está), y **el direccionamiento estable de la persona (cola offline, threads, DMs) sigue siendo la pubkey maestra del daemon**, que es quien tiene el socket vivo del daemon. El navegador delegado NO necesita recibir DMs como la maestra; recibe respuestas del vault por su propia conexión efímera.
- **Routing del store en claro por el proxy es un retroceso de privacidad** frente al Drive E2E actual (`sync.js` cifra AES-256-GCM antes de subir). Decisión: **las ops del store van cifradas de cara al proxy desde la fase 3 (v1 del routing), no "v2"** — se reusa el cifrado E2E de `@dotrino/identity` con la clave de cifrado del vault.
- **`recordOpen` es un contador incremental** (`store.js:267-273`), y reconciliar por `max(count)` pierde aperturas. Decisión: el store envía el **valor absoluto** (`set count=N`), no un incremento, y la reconciliación es last-writer-by-ts sobre ese valor.

---

## 2. Identidad delegada — mecanismo concreto

**Regla de oro:** firma local con `D` **solo para el transporte**; **re-enruto a la maestra del daemon (`vault.sign`)** para todo lo que otra persona/servicio verifique como tu identidad. Esto evita el agujero bloqueante del proxy y la confusión de identidad.

### Cambios en `@dotrino/identity`

**`dotrino-identity/vault/vault-protocol.js` (NUEVO).** Mover aquí las constantes `MSG`/`SCOPE` que hoy viven en `dotrino-vault/src/protocol.js`, para que `@dotrino/identity` sea el dueño del contrato de mensajes y el daemon lo importe (el daemon ya depende de `@dotrino/identity`). Re-exportar desde `dotrino-vault/src/protocol.js` para no romper daemons desplegados (compat: `export { MSG, SCOPE } from '@dotrino/identity/vault-protocol'`). Se añaden `SCOPE.STORE='vault:store'`, `MSG.STORE_OP`, `MSG.STORE_RES` (ver §3).

**`dotrino-identity/vault/remote.js` (NUEVO).** `createRemoteVault({ device, cert, master, proxyUrl })` con import dinámico (lazy) de `@dotrino/proxy-client` SOLO al entrar en remote mode:
- `enroll(qr, deviceKey)` → `connect` + `identify` firmado por `D` + `sendByPubkey(qr.iss, {type: MSG.ENROLL, dpub, token, label})` + espera `MSG.ENROLLED`. Es el flujo ya validado en `dotrino-vault/src/client.js:40-46`, movido al navegador.
- `requestMasterSign(payload)` → firma el sobre con `D`, adjunta el `cert`, `sendByPubkey(master, {type: MSG.SIGN, data, signature, cert})`, espera `MSG.SIGNED` y devuelve `{ signature, publickey: master }` (firma REAL de la maestra; la priv nunca sale del PC).

**`dotrino-identity/vault/core.js` (modificar `createIdentityCore`).** Nuevas claves kv junto a `KEY_STORAGE`:
- `DEVICE_KEY_STORAGE = 'dotrino.identity.device'` → `{ privateJwk, publicJwk, publickey, deviceId }` (generado con `makeDeviceKey`).
- `VAULT_CERT_STORAGE = 'dotrino.identity.vault-cert'` → `{ cert, master, proxy, enrolledAt }`.

Nuevos handlers:
- `vaultPair({ qr })`: genera `D` si no existe → `createRemoteVault().enroll` → persiste device+cert+master+proxy → `remoteMode=true` → emite evento `vault {status:'paired'}`.
- `vaultUnpair()`: borra `DEVICE_KEY_STORAGE`+`VAULT_CERT_STORAGE`, `remoteMode=false`. **No** toca `KEY_STORAGE`.
- `vaultStatus()`: `{ paired, deviceId, master, exp, online }`.

`signData({ data, master })` **reescrito** con bifurcación:
- **Sin pairing (default actual):** firma con la maestra local del iframe → `{ signature, publickey: publickeyJwkStr }`. **Idéntico a hoy** (`core.js:461-465`).
- **Con pairing y cert vigente** (validado con `verifyDelegation({cert, expectedSub: device.publickey, now})`):
  - **default y `op:'identify'`:** distinguir dos sub-casos. Para **identidad/datos de app** (lo que verifica otra persona): re-enruta `requestMasterSign(data)` → devuelve `{ signature, publickey: master }` (pubkey **estable** del daemon). Para **`op:'identify'` del proxy**: firma **local con D** → `{ signature, publickey: device.publickey }` (el proxy lo acepta; el navegador se conecta como D).
  - Si el daemon está offline y la operación necesita la maestra → error `'vault-offline'` y la app cae al comportamiento previo o reintenta (la cola offline 24 h del proxy entrega el `MSG.SIGN` cuando el daemon vuelve en <24 h, pero `signData` es síncrona para el llamador, así que se devuelve error y se reintenta).

El retorno gana un campo opcional `cert` **solo cuando** la firma fue local con `D` (caso identify); los consumidores viejos lo ignoran. **No se cambia el default de identidad**: en modo delegado tu identidad pública sigue siendo UNA pubkey estable (la del daemon), no `D`.

**`dotrino-identity/src/index.js` (cliente navegador):** thin wrappers `enrollDevice(qr)`, `unpairDevice()`, `vaultStatus()`, `onVault(h)`, y `signData(data, opts)` con passthrough de `{ master }`. **`src/index.d.ts`** y **`src/node.js`** actualizados (el daemon sigue firmando local sin remote mode).

**Auditoría obligatoria (parte de la fase):** `identify` en `@dotrino/proxy-client` y en cada app (p.ej. `dotrino-messenger/src/stores/connectionStore.js`). El iframe detecta `op:'identify'` y auto-selecciona el camino D (no requiere que las apps pasen flags). Reputation: `setRating` firma con `publickeyJwkStr`; en modo delegado debe re-enrutar a `requestMasterSign` para que las atestaciones queden emitidas por la maestra estable y `aggregateTrust` las ligue a la identidad — esto añade `@dotrino/reputation` a la lista de auditoría (no se firma reputación con D).

---

## 3. Routing del store — mecanismo concreto

**El daemon NO tiene modelo de threads** (`dotrino-vault/src/store.js`: árbol `folder/children`). Por tanto se añade un **sub-store de threads+opens paralelo** en el daemon con la MISMA semántica del iframe, no se mapea threadKey→nodo del árbol (descartado el openQuestion por costoso/ambiguo).

**El canal de respuesta:** el vault responde por el `from` token de la conexión efímera (`vault.js:60-61`). Decisión: el store usa **conexión efímera por lote de ops con `waitFor(rid)` y timeout corto (~6 s)**; la respuesta sobrevive mientras la conexión viva. Si la conexión muere, **la op se reintenta** (las escrituras son idempotentes por `id`; los reads simplemente se re-piden). No se intenta entregar la respuesta por la cola offline 24 h (eso es para writes fire-and-forget direccionados a la maestra, no para respuestas a una conexión efímera del navegador).

### `dotrino-vault/src/protocol.js` (vía `vault-protocol.js`)
- `SCOPE.STORE = 'vault:store'` (aditivo; no toca `vault:sign`/`vault:read`).
- `MSG.STORE_OP = 'vault.store'` (device→vault: `{ data:{op,args,publickey,ts,rid}, signature, cert }`, todo `data` cubierto por la firma de `D`).
- `MSG.STORE_RES = 'vault.store.res'` (vault→device: `{ rid, result }`).
- `data.op ∈ { appendMessage, listThread, listThreadKeys, getThreadSummaries, removeThread, removeMessage, recordOpen, getOpens, clearOpens, getStats, importThreads, clearAll, setMaxPerThread }` — **todas** las ops mutadoras se enrutan (las críticas señalaron que omitir `clearAll`/`importThreads`/`setMaxPerThread` deja cache y vault inconsistentes).

### `dotrino-vault/src/store.js`
- `SCHEMA_VERSION` → 2; `data.threads = {}` y `data.opens = {}` junto a `data.tree`. Migración trivial: si faltan, inicializar vacíos (no toca el árbol existente).
- Lógica de threads/opens con dedup por `id`, `trimThread(maxPerThread)`, `mergeThreads` por `id+ts`, opens `{count,ts}` con **set absoluto** (no incremento).

### `@dotrino/store/store/merge.js` (NUEVO, ESM puro)
Factorizar `mergeThreads`/`trimThread` (`store.js:211,254`) a un módulo puro que **recibe `maxPerThread` como argumento** (hoy cierra sobre la variable module-level mutable — la crítica acertó: extraerlo requiere cambiar la firma). Lo importan tanto el iframe como el daemon. Riesgo de regresión en el path de sync de Drive acotado por tests de merge antes de cortar.

### `dotrino-vault/src/vault.js`
- `handleStore(from, p)`: `verifyChain({ expectedScope: SCOPE.STORE, trustedIssuer: master, revoked })` → dispatch `op` → `reply(from, { type: MSG.STORE_RES, rid, result })`. Rechaza `ts` fuera de ventana (anti-replay; escrituras además dedup por `id`).

### `dotrino-store/store/vault-backend.js` (NUEVO) + `store/store.js`
**Build:** el iframe se sirve hoy como ES module crudo sin bundler (`store/index.html` → `<script type=module src=./store.js>`, solo importa `./sync.js`). La crítica acertó: `import '@dotrino/...'` no resuelve. Decisión: **vendorizar** `@dotrino/proxy-client` y `capabilities` como archivos estáticos en el origin `store.dotrino.com` e importarlos por ruta **relativa** (`./vendor/proxy-client.js`, `./vendor/capabilities.js`), versionados con el deploy del store. Carga **perezosa y aislada**: `vault-backend.js` solo se importa cuando `isPaired()` es true, para que el bootstrap del iframe sin pairing sea idéntico a hoy (no se toca `store/index.html` salvo añadir `/vendor`).
- `isPaired()`: hay `vault.pairing.v1` en el objectStore `kv` (origin del store).
- `enroll({qr,label})`: `makeDeviceKey` → flujo enroll → guarda `{ iss(master), proxy, device, cert(scope vault:store) }`.
- `call(op, args)`: `connect` + `identify` firmado por `D` + `sendByPubkey(iss, {type:MSG.STORE_OP, data:{op,args,publickey,ts,rid}, signature, cert})` + `waitFor(rid, 6000)`. **`args` cifrados E2E** con la clave de cifrado del vault (no en claro ante el proxy).

Cada handler de `store.js` se vuelve wrapper: si `isPaired()` y la op está enrutada → intenta `vaultBackend.call`; en éxito espeja el resultado al IndexedDB local (cache) y responde; en fallo/timeout → cae al backend IndexedDB actual (comportamiento de hoy) y marca pendiente. **IndexedDB es siempre cache durable**: las escrituras offline nunca se pierden; al reconectar, reenvía pendientes como `appendMessage` (dedup por `id`) y hace `mergeThreads(local, remote)` en lecturas. `getStats` reporta `backend:'vault'` cuando emparejado, pero el `usage` real del disco del PC no es consultable desde el iframe → reporta el uso del **cache local** con etiqueta `backend:'vault'` (limitación documentada, no se inventa un número del disco del PC).

**`dotrino-store/src/index.js`:** wrappers `vaultStatus()`, `vaultEnroll(qr,label)`, `vaultUnlink()`, `onVault(h)`.

---

## 4. UX de emparejar — en `dotrino_profile`

Pantalla en el modo `self` (tu propio perfil), bloque "Tu bóveda · Dispositivos" debajo de `<dotrino-profile>` (`dotrino_profile/src/main.js`, render por `innerHTML` como el resto). Profile es **otro origin**: no custodia nada; orquesta el pairing como control remoto de los iframes compartidos. Profile ya embebe `Identity.connect()` (iframe `id.`); para el store debe además embeber `Store.connect()` (iframe `store.`) y llamar sus métodos `vault*`.

**Estados:**
- **(a) No vinculado:** tarjeta "Conecta este dispositivo a tu bóveda" con dos vías para ingresar el objeto `{v,iss,proxy,token}` que imprime `dotrino-vault pair`: **pegar el JSON** o **escanear el QR** con la cámara (reusar el decoder client-side de `qrreader`/`qrshare`, sin librería de terceros nueva). Antes de confirmar, mostrar el **fingerprint del `iss`** para verificación visual. Al confirmar:
  - Identidad: `Identity.enrollDevice(qr)` (cert scope `vault:sign`).
  - Store: `Store.vaultEnroll(qr, label)` (cert scope `vault:store`).
  - El daemon **muestra/confirma el `deviceId` enrolado** (no solo loguea el label) para cerrar el secuestro de slot que las críticas señalaron.
- **(b) Vinculado:** "Conectado a tu bóveda · id `<fp>`" + "Desconectar este dispositivo" (`Identity.unpairDevice()` + `Store.vaultUnlink()`).
- **(c) Gestión de dispositivos:** fase 1 muestra solo el dispositivo local; revocar otros se hace por CLI `dotrino-vault revoke` (panel remoto con `vault:admin` queda para fase posterior, sin diseñar aún).

**Qué guarda y dónde:** la device-key + cert de **identidad** en el localStorage del iframe `id.dotrino.com`; la device-key + cert de **store** en el IndexedDB del iframe `store.dotrino.com`. Profile no guarda llaves.

**Drive vs bóveda:** al vincular el store, **se desactiva el sync de Drive** y se muestra "Tu bóveda reemplaza a Google Drive". Para evitar pérdida en el ciclo vincular/desvincular, al desvincular se **re-ofrece reconectar Drive** y el cache local conserva el histórico (no se borra). La migración inicial local→bóveda es un paso **manual** "Subir mis datos a la bóveda" (one-shot `importThreads`), no automática, para no duplicar datos grandes ni marcar como subido algo que falló.

---

## 5. Fases ordenadas

### Fase 1 — Emparejamiento + cert en el iframe de identidad (bajo riesgo, entregable)
**Objetivo:** poder enrolar un dispositivo desde profile y guardar el cert delegado en `id.dotrino.com`, sin cambiar todavía el comportamiento de `signData` (remote mode existe pero el default de firma NO cambia hasta fase 2).
- Archivos: `dotrino-identity/vault/vault-protocol.js` (NUEVO, mueve `MSG`/`SCOPE`), `dotrino-vault/src/protocol.js` (re-export para compat), `dotrino-identity/vault/remote.js` (NUEVO, solo `enroll`), `dotrino-identity/vault/core.js` (`DEVICE_KEY_STORAGE`/`VAULT_CERT_STORAGE`, handlers `vaultPair`/`vaultUnpair`/`vaultStatus`), `dotrino-identity/src/index.js` (+`.d.ts`), `dotrino_profile/src/main.js` (pantalla pegar/escanear + fingerprint).
- **Hecho cuando:** desde profile se pega/escanea el QR de un daemon real, `vaultStatus()` devuelve `paired:true` con `deviceId` y `exp`, el daemon confirma el `deviceId`, y `vaultUnpair()` revierte. `signData` sin opts sigue firmando con la maestra local (sin regresión, verificado con messenger/reputation). Daemon desplegado sigue funcionando (compat del re-export probada).

### Fase 2 — Identidad delegada (re-enrutar `signData` a la maestra)
**Objetivo:** que las firmas de identidad salgan de la maestra del daemon vía cert.
- Archivos: `dotrino-identity/vault/core.js` (`signData` bifurcado: master por re-enruteo, D solo para `op:identify`), `dotrino-identity/vault/remote.js` (+`requestMasterSign`), `dotrino-vault/src/vault.js` (ya soporta `MSG.SIGN`; verificar `verifyChain` con scope `vault:sign`). Auditoría: `@dotrino/proxy-client` identify, `dotrino-messenger/src/stores/connectionStore.js`, `@dotrino/reputation` (re-enrutar `setRating`).
- **Hecho cuando:** con pairing, `signData(data)` devuelve `publickey == master-del-daemon` (estable, igual para todas las apps), una firma generada en el navegador valida contra la maestra del daemon, `identify` del proxy funciona con `D`, y con el daemon offline `signData` devuelve `vault-offline` sin colgar. Reputación emitida queda atribuida a la maestra estable. Sin pairing, todo idéntico a fase 1.

### Fase 3 — Routing del store a la bóveda (cifrado de cara al proxy)
**Objetivo:** que el store lea/escriba en la bóveda, con IndexedDB como cache.
- Archivos: `dotrino-vault/src/protocol.js` (`SCOPE.STORE`, `MSG.STORE_OP/STORE_RES`), `dotrino-vault/src/store.js` (SCHEMA 2, threads/opens, opens absoluto), `dotrino-vault/src/vault.js` (`handleStore` + `verifyChain` scope store + anti-replay), `dotrino-store/store/merge.js` (NUEVO, puro, `maxPerThread` por arg), `dotrino-store/store/vault-backend.js` (NUEVO, vendor proxy-client/capabilities, ops cifradas), `dotrino-store/store/store.js` (wrappers con fallback + cache), `dotrino-store/store/index.html` (`/vendor`), `dotrino-store/src/index.js` (`vaultEnroll`/`vaultUnlink`/`vaultStatus`/`onVault`), `dotrino_profile/src/main.js` (enrolar store + "subir mis datos" + Drive off).
- **Hecho cuando:** con store emparejado, `appendMessage`/`listThread`/`recordOpen` (valor absoluto) hacen round-trip cifrado a la bóveda y espejan en cache; con el daemon offline caen a IndexedDB y reconcilian al volver (merge idempotente por `id+ts`); todas las ops mutadoras enrutan (no quedan cache/vault inconsistentes); el proxy NO ve contenido de threads en claro. Sin pairing, byte-idéntico a hoy (verificado en messenger/home/chat).

### Fase 4 (posterior, fuera de alcance inmediato) — panel remoto de dispositivos
`vault:admin` para `list`/`revoke` desde el navegador, con designación segura del dispositivo "dueño". No se implementa hasta resolver cómo se designa el dueño sin que el primer enroll (potencialmente de un token interceptado) lo sea.

---

## 6. Qué se rompe y riesgos top

**Qué se rompe: nada, si se respeta el gate opt-in.** Sin pairing, `signData` firma con la maestra local (idéntico) y el store usa IndexedDB+Drive (idéntico); la API `postMessage` de ambos iframes no cambia y ningún cliente viejo llama los métodos `vault*`. El cambio de dueño de `MSG`/`SCOPE` se hace con re-export para no romper daemons desplegados. SCHEMA 2 del vault migra agregando `threads`/`opens` vacíos sin tocar el árbol.

**Riesgos top y mitigación:**

1. **Identidad doble (maestra del navegador ≠ maestra del daemon).** Mitigación: en modo delegado, `signData` re-enruta a la maestra del daemon → tu identidad pública pasa a ser **una sola** pubkey estable (la del daemon). La maestra del navegador queda como legacy y no se borra. **Caveat irreductible:** el contenido firmado mientras estabas con la maestra del navegador (ratings, pins) sigue atribuido a esa pubkey; emparejar **cambia tu identidad pública** hacia adelante, no migra el pasado. Documentar en la UX ("este dispositivo firmará con tu bóveda").

2. **El proxy no entiende delegación (bloqueante de la propuesta original).** Mitigación adoptada: identify como `D` (válido para el proxy tal cual); la persona se direcciona por la maestra del daemon (que tiene socket vivo); el navegador recibe respuestas por su conexión efímera, no necesita DMs como la maestra.

3. **Privacidad del routing del store.** Mitigación: ops cifradas E2E de cara al proxy **desde fase 3** (no diferido a "v2"), reusando el cifrado del vault. Se mantiene paridad con el Drive E2E actual.

4. **Lecturas dependientes del daemon online (regresión UX).** Mitigación: IndexedDB es cache read-through con timeout corto (~6 s) y fallback; con el PC apagado las apps leen del cache local (no se cuelgan). Se acepta que, bajo latencia de internet, el cache cubre buena parte — la bóveda es la verdad cuando hay red, el cache cuando no.

5. **Revocación delegada no verificable por terceros** (la lista vive en el daemon). Mitigación parcial: tope duro 30 días + scope mínimo (`vault:store` no firma identidad; `vault:sign` solo para identidad). Un cert robado solo daña dentro de su ventana y de su scope; la maestra nunca sale del PC. Un endpoint público de revocación queda como mejora futura (no en este alcance).

6. **Blast radius del iframe `store.`** (XSS en ese origin = device-key de todas las apps). Mitigación: scope acotado `vault:store`, exp corto, vendor versionado, y el postMessage del store con allowlist de origin del parent para que un embebedor hostil no dispare `vaultEnroll`/`vaultUnlink`.

7. **Refactor de `mergeThreads` toca el path de sync de Drive vivo.** Mitigación: el módulo puro recibe `maxPerThread` por argumento; tests de merge (incluido el path de Drive) antes de cortar.

**Archivos nuevos clave:** `/mnt/sda1/Dotrino/dotrino-identity/vault/vault-protocol.js`, `/mnt/sda1/Dotrino/dotrino-identity/vault/remote.js`, `/mnt/sda1/Dotrino/dotrino-store/store/merge.js`, `/mnt/sda1/Dotrino/dotrino-store/store/vault-backend.js`. **Hechos verificados en código:** `dotrino-proxy/server.js:1496-1548` (identify contra JWK literal), `dotrino-vault/src/vault.js:60-61` (reply por token), `dotrino-vault/src/store.js:11-57` (árbol folder/children, sin threads), `dotrino-vault/src/protocol.js` (solo SIGN/GET, scopes sign/read), `dotrino-store/store/store.js:211-273` (merge con `maxPerThread` module-level; `recordOpen` incremental), `dotrino-identity/vault/core.js:23,461-465` (maestra en el navegador, `signData` actual).