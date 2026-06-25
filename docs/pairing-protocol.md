I have everything needed. Writing the hardened pairing protocol decision document now.

---

# Protocolo de emparejamiento del vault de Dotrino — Diseño endurecido (documento de decisión)

Estado: APROBADO para implementación. Reemplaza el flujo de token al portador (bearer) hoy implementado en `dotrino-vault/src/{vault.js,client.js,ctl.js,daemon.js}`.

Resumen ejecutivo: el emparejamiento actual concede un certificado firmado por la maestra a **cualquiera que presente el token de 5 min**, con `scope` por defecto `[vault:sign, vault:read]` y sin confirmar qué clave de dispositivo se autoriza (`handleEnroll`, `vault.js:64-76`). Esto produce robo total de datos y secuestro de identidad por simple ingeniería social (relay del QR). El diseño endurecido elimina el token al portador como autoridad suficiente: el dispositivo prueba posesión de su clave `D`, el dueño **confirma en el PC** un código corto de autenticación mutuo (SAS) derivado del `deviceId`, el dispositivo **valida la cadena** del cert que recibe contra el `iss` que el usuario vio, y el `scope` por defecto baja a mínimo. Se añade el self-wipe por revocación **autenticado por firma de la maestra** (cierra el wipe-DoS).

---

## 1. Flujo de emparejamiento endurecido (cierra el hueco "ingresar el código del atacante")

### 1.1 Principio de diseño

La autorización de un dispositivo nuevo se ancla a **tres** cosas, no a un secreto al portador:

1. **Posesión de la clave `D`** del dispositivo (prueba criptográfica, no "presentar un string").
2. **Confirmación humana en la máquina de la maestra** del `deviceId` concreto que se autoriza.
3. **Verificación de un Short-Authentication-String (SAS) mutuo** que el humano compara visualmente entre las dos pantallas — esto es lo que mata el relay/phishing: el atacante remoto **no puede mostrar el SAS correcto en el dispositivo físico de la víctima**.

El token de pairing deja de ser "autoridad". Pasa a ser solo un **localizador de sesión** de baja sensibilidad: dice *a qué vault hablar y en qué ventana*, pero **no** basta para obtener un cert. Por eso el flujo es robusto aunque el token se filtre (foto del QR, copia-pega a un falso soporte, proxy malicioso que lo lee en claro).

### 1.2 Flujo paso a paso

Notación: `M` = pubkey maestra del daemon (vault); `D` = par de claves del dispositivo (`makeDeviceKey`, `capabilities.js:65`); `deviceId = pubkeyId(D.publickey)` (`capabilities.js:50`); `SAS` = 6 dígitos derivados deterministamente de `(M, D, sessionNonce)`.

```
DISPOSITIVO (profile.dotrino.com / app)              VAULT (PC, daemon, custodia M)
──────────────────────────────────────              ──────────────────────────────
                                                     (1) `dotrino-vault pair`:
                                                         - genera sessionToken (128b) + sessionNonce
                                                         - estado: AWAITING_ENROLL
                                                         - imprime QR { v:2, iss:M, proxy, token,
                                                           sn: sessionNonce }
                                                         - banner rojo de scope/advertencia
                                                         - NO escribe pair.json en disco
                                                           (solo memoria del daemon; ver §5)
(2) usuario escanea/pega el QR.
    El DISPOSITIVO genera D = makeDeviceKey().
(3) construye data = { op:'enroll', dpub:D.publickey,
       token, sn, label, ts }
    firma con D: sig = signWithDevice(D, data)
    ───── sendByPubkey(M, {ENROLL, data, sig}) ─────▶
                                                     (4) handleEnroll:
                                                       - pend = pending.get(token); válido/no usado/no exp
                                                       - rawVerify(dpub, canon(data), sig)  ← PRUEBA DE POSESIÓN
                                                       - sn === pend.sn
                                                       - calcula deviceId = pubkeyId(dpub)
                                                       - calcula SAS = HKDF(M ‖ dpub ‖ sn) → 6 díg
                                                       - estado pend → PENDING_CONFIRM(dpub,deviceId,SAS)
                                                       - responde {ENROLL_CHALLENGE, deviceId, sas:SAS}
                                                       - MUESTRA en el PC:
                                                         "Dispositivo XQ7F-3K9P quiere enrolarse.
                                                          Código: 418 027. ¿Aprobar? (dotrino-vault
                                                          approve XQ7F-3K9P  /  rechazar)"
                                  ◀──── {ENROLL_CHALLENGE, deviceId, sas} ────
(5) el DISPOSITIVO muestra en su pantalla:
      "Tu código: 418 027 — deviceId XQ7F-3K9P.
       Confírmalo en tu PC."
(6) EL USUARIO COMPARA los dos códigos
    (pantalla del dispositivo ↔ pantalla del PC).
    Solo si COINCIDEN, teclea en el PC:
                                                     (7) `dotrino-vault approve XQ7F-3K9P`:
                                                       - el dueño confirma el deviceId+SAS visto
                                                       - SOLO ahora: signDelegation(dpub, scope, ttl)
                                                         (scope mínimo por defecto; ver §1.4)
                                                       - pend.used = true; pending.delete
                                  ◀──── {ENROLLED, cert, iss:M, sas} ────
(8) el DISPOSITIVO valida ESTRICTAMENTE antes de persistir:
      verifyChain({ data:{publickey:D.publickey}, ...,
                    cert, trustedIssuer: qr.iss,
                    expectedSub: D.publickey,
                    expectedScope }) === ok
      AND cert.iss === qr.iss   (el iss que el USUARIO vio, NO res.iss)
      AND cert.sub === D.publickey
    si falla → descarta, NO empareja.
    si ok → guarda { device:D, cert, master: qr.iss, proxy: qr.proxy }
```

### 1.3 Qué verifica cada lado (resumen de invariantes)

| Lado | Verifica | Cierra |
|---|---|---|
| Vault (paso 4) | `rawVerify(dpub, data, sig)` — el remitente posee la privada de `D` | Un proxy/atacante que solo *vio* el token no puede enrolar **su** pubkey sin firmar con esa pubkey; y firmar con la pubkey de la víctima es imposible (no tiene su privada) |
| Vault (paso 7) | Confirmación humana del `deviceId` + SAS **antes** de `signDelegation` | Relay del QR a soporte falso: el dueño ve un `deviceId`/SAS que no reconoce y rechaza |
| Usuario (paso 6) | SAS pantalla-dispositivo == SAS pantalla-PC | Man-in-the-middle/relay: el SAS del dispositivo del atacante **no** aparece en el dispositivo físico de la víctima |
| Dispositivo (paso 8) | `verifyChain` + `cert.iss === qr.iss` + `cert.sub === D.publickey` | Inyección de cert de **otra** maestra por un proxy/atacante que conteste primero (re-pairing silencioso) |

### 1.4 Formato del código y por qué NO depende de un secreto

El **QR/objeto** (`{ v:2, iss:M, proxy, token, sn }`) deja de ser sensible en el sentido de "quien lo tiene gana", porque:

- El `token` ya **no autoriza nada por sí solo**: para obtener un cert hay que (a) probar posesión de `D` y (b) que el dueño apruebe el `deviceId` en el PC. Filtrar el token solo permite *iniciar* un challenge que el dueño verá y rechazará si no lo reconoce.
- El **SAS de 6 dígitos** es el control anti-phishing, y **no es secreto transmisible**: se deriva de `(M, D, sn)` y solo tiene valor *comparado entre las dos pantallas presentes*. Un atacante remoto no puede inyectar su SAS en la pantalla del dispositivo legítimo de la víctima.
- El `deviceId` (`pubkeyId(dpub).slice(0,8)`, agrupado legible tipo `XQ7F-3K9P`) es **público por diseño** (es un hash de una pubkey); su función es ser reconocible/comparable por el humano, no secreto.

Esto es la "dirección invertida" del diseño implementada de verdad: la **aprobación ocurre en la máquina que tiene la maestra**, y la decisión humana está atada a un código que el dispositivo legítimo muestra. No hay ningún secreto al portador cuya mera posesión conceda acceso.

---

## 2. PIN + BORRADO: las tres acciones separadas, con el trigger de self-wipe autenticado

Se separan **explícitamente** tres acciones, cada una con su gesto y su consecuencia de datos. Ninguna es implícita.

### 2.1 CONECTAR (vincular por primera vez) — NO borra

Precondición: el dispositivo no tiene cert previo (`VAULT_CERT_STORAGE` vacío). Ejecuta el flujo §1. **No borra nada**: los datos locales (IndexedDB del store, identidad local) se conservan y se **suben** a la bóveda como paso manual "Subir mis datos a la bóveda" (`importThreads`, idempotente por `id`). Sin pérdida.

### 2.2 MOVER IDENTIDAD (cambiar de vault A → B) — borra, con doble confirmación

Precondición: ya hay cert de `A`. Cambiar a `B` es una acción **muy advertida**: el dispositivo muestra "Vas a desconectarte de tu bóveda actual y conectarte a otra. Se BORRARÁN los datos locales de este dispositivo (store + identidad de dispositivo) para empezar limpio." Requiere:

1. Confirmación textual explícita (escribir "CAMBIAR" o equivalente), no un solo clic.
2. El flujo §1 completo contra `B` (incluido el SAS comparado).
3. Solo tras enrolar con éxito en `B`, se ejecuta el **clean-slate local**: borra `DEVICE_KEY_STORAGE` + `VAULT_CERT_STORAGE` del store y de identidad, y limpia el cache local. **No** se toca `KEY_STORAGE` (la maestra legacy del navegador) salvo que el usuario lo pida.

El borrado aquí es **local y disparado por el propio usuario** en su dispositivo; no llega por la red, así que no hay superficie de wipe-DoS.

### 2.3 REVOCAR (robo) — self-wipe disparado por la maestra, AUTENTICADO

Este es el punto crítico (hueco "wipe-DoS"). El borrado remoto **NUNCA** se dispara por un `MSG.ERROR`/"no autorizado" del proxy (forjable por cualquiera que conozca la pubkey pública del dispositivo). Se introduce un mensaje dedicado, **firmado por la maestra**:

```
MSG.REVOKED = 'vault.revoked'
cuerpo firmado por M:  body = { op:'revoke', sub: D.publickey, nonce, iat, exp }
sobre:  { type: MSG.REVOKED, body, sig }   donde sig = M.signData(canon(body))
```

Regla de oro del dispositivo (cierra wipe-DoS):

> El self-wipe solo se ejecuta si `rawVerify(masterPineado, canon(body), sig)` es verdadero, donde `masterPineado === qr.iss` guardado al emparejar (`VAULT_CERT_STORAGE.master`), Y `body.sub === D.publickey`, Y `body.op === 'revoke'`, Y `now <= body.exp`. Un `MSG.ERROR` plano, un "revocado" sin firma, o una firma de cualquier clave distinta a la maestra pineada **se ignoran** (a lo sumo: degradar/reintentar, jamás destruir datos).

Distinción obligatoria **expirado ≠ revocado**: un cert simplemente expirado dispara **re-enroll/renovación**, nunca wipe. Solo una revocación firmada explícita borra.

Entrega: el daemon, al `dotrino-vault revoke <deviceId>`, emite `MSG.REVOKED` por `sendByPubkey(D.publickey, …)` y lo **reintenta**; el proxy lo encola en la **cola offline 24 h**, de modo que un dispositivo que vuelve dentro de 24 h recibe el wipe al reconectar.

### 2.4 Ventana del ladrón offline (mitigación, no eliminación)

Propiedad irreductible del modelo: un cert + privada de `D` ya **exfiltrados** sobreviven mientras el ladrón esté offline (no recibe el `MSG.REVOKED`), y **los datos ya leídos no se "des-roban"**. Mitigaciones que **acotan la ventana**:

- **`exp` corto por defecto** (ver §1.4 / tabla): bajar a horas para `vault:store`/`vault:read` y exigir **renovación autenticada periódica** (heartbeat firmado por `D`, que el daemon solo concede si el `deviceId` no está revocado). Un cert robado caduca pronto **sin** depender de que el daemon esté online en el instante del robo.
- **Scope segregado** (§1.4): un cert robado solo daña su eje (no `[sign,read]` juntos por defecto).
- **Clave `D` no-extraíble en el navegador** (`CryptoKey` `extractable:false` en IndexedDB): un XSS puede *usar* `D` mientras vive el origin pero **no exfiltrarla** a otra máquina → degrada "ladrón remoto persistente" a "mientras dure el XSS en esa pestaña".
- **Detección**: el daemon registra `deviceId`/IP por request y alerta ante uso del mismo cert desde dos orígenes simultáneos (señal de clonación) para revocar antes de `exp`.

Se documenta explícitamente: la revocación es **forward-only**; el self-wipe protege al **dispositivo víctima honesto** (limita exposición futura), **no** es contramedida contra un portador hostil.

---

## 3. Por qué el auto-sync siempre-activo es seguro con este flujo

La premisa del diseño ("auto-sync solo manda datos a TU vault") se sostiene **solo si emparejar con un vault ajeno es imposible**. El flujo endurecido garantiza eso por dos cierres independientes:

1. **El dispositivo pinea `qr.iss` y valida la cadena** (paso 8): el cert que persiste **debe** estar firmado por la maestra que el usuario vio en el QR (`cert.iss === qr.iss`, con `verifyChain` contra ese `trustedIssuer`). Un proxy/atacante que conteste primero con un cert de **otra** maestra es rechazado. Por tanto, `VAULT_CERT_STORAGE.master` siempre es la maestra que el humano aprobó.
2. **El auto-sync cifra E2E hacia `qr.iss` pineado**, no hacia un `iss` devuelto por la red. Como el destino del sync es la maestra verificada, el auto-sync **no puede** exfiltrar a un vault atacante aunque el proxy sea hostil.

Consecuencia: con el cert anclado a la maestra correcta, **auto-sync siempre-on = subir a tu propio vault, siempre**. No hace falta un paso manual de sync.

**Lo que falta para cerrarlo del todo** (residual): el primer GET tras emparejar debe ser un **challenge-response** (el dispositivo manda un nonce; la maestra firma; el dispositivo valida contra `qr.iss`) para confirmar *en vivo* que el vault al otro lado realmente controla la privada de `qr.iss` antes de empezar a subir datos. Sin esto, un proxy podría tragarse el tráfico de sync (DoS), aunque **no** descifrarlo ni redirigirlo a otra maestra. Se incluye en Fase 2.

---

## 4. Tabla de amenazas → defensa que la cierra; y residuales

| # | Ataque confirmado (sev) | Defensa del protocolo endurecido | Residual |
|---|---|---|---|
| A1 | Robo del QR/token + redención con dpub del atacante (critical) | Prueba de posesión de `D` (paso 4) + confirmación humana del `deviceId`+SAS (paso 6-7). El token solo ya no autoriza | Token filtrado permite *iniciar* un challenge; el dueño debe rechazar correctamente (UX + copy) |
| A2 | Relay del QR disfrazado de soporte (critical) | SAS mutuo comparado entre pantallas (paso 6): el atacante remoto no muestra el SAS en el dispositivo físico de la víctima | Usuario que aprueba "a ciegas" sin comparar SAS — mitigado por copy y por mostrar el `deviceId` esperado |
| A3 | Robo del token por proxy malicioso / enroll-stealing (critical) | Posesión de `D` (el proxy ve el token pero no puede firmar como otra `D`) + pin de `qr.iss` en el dispositivo | Proxy puede hacer DoS del enroll (descartar mensajes); no roba acceso |
| A4 | Sustitución del issuer `iss` por el proxy (high) | Paso 8: `cert.iss === qr.iss`, ignorar `res.iss`; `verifyChain(trustedIssuer: qr.iss)` | Ninguno relevante (sin la privada de `qr.iss` el proxy no forja un cert válido) |
| A5 / A12 | Inyección de cert de otra maestra / re-pairing silencioso (critical) | Paso 8 estricto: `verifyChain` ok + `iss`/`sub` correctos antes de persistir | Ninguno |
| A6 | Reply-to-token entrega el cert al atacante (high) | El cert se emite solo tras aprobación humana y se liga a `D`; sin aprobación no hay cert que entregar | Subsumido por A1 |
| A7 | Phishing amplificado por el proxy (high) | Aprobación por-dispositivo en el PC (paso 7) | UX-dependiente (igual que A1) |
| A8 | Proxy se hace pasar por el vault en el handshake (high) | Paso 8 + challenge-response del §3 | DoS del handshake por el proxy |
| A9 | Ladrón offline conserva cert revocado (high/medium) | `MSG.REVOKED` firmado + cola offline 24h + `exp` corto + renovación autenticada | **Residual real**: exfil pasada irrecuperable; ladrón permanentemente offline no recibe wipe → acotado solo por `exp` |
| A10 | Cert al portador exfiltrado (lectura/firma remota) (high) | `exp` corto, scope segregado, `D` no-extraíble en navegador, identify firmado por `D` ligado a la conexión | Dentro de la ventana de `exp`, un cert+privada robados funcionan — mitigado, no eliminado |
| A11 | Ventana del LADRÓN sin rotación de maestra (high) | `exp` corto + renovación; **rotación de maestra** como mejora (firma nueva maestra por la vieja con marca "comprometida desde T") | Rotación de maestra queda fuera del alcance inmediato; firmas dentro de la ventana indistinguibles hasta implementarla |
| A13 | Wipe-DoS por revocado falso no autenticado (latente) | §2.3: self-wipe solo con firma de `M` pineada; `MSG.ERROR` jamás dispara borrado | Ninguno (cerrado por diseño) |
| A14 | Race de re-pairing / robo de slot (medium) | Confirmación humana sincrónica + notificación persistente de cada enroll + alerta de "token ya consumido" | Subsumido por A1; reducido a evento visible |
| A15 | Persistencia/camuflaje (múltiples certs, label falsificable) (low) | Mostrar `deviceId` (`sub`) en `devices` y en el log de enroll; `revoke --all-except`; rotar token tras enroll | Auditabilidad mejorada; label sigue siendo libre (marcar duplicados) |
| A16 | Copy sin advertencia de scope (medium) | Banner rojo de scope en `pair` + scope mínimo por defecto + confirmación interactiva | UX-dependiente |
| A17 | `handleGet(id:'root')` = volcado total (low) | Scope acotado a subárbol (`vault:read:<nodeId>`), paginación, rate-limit/alerta | Defensa en profundidad; depende de A1 estar cerrado |

Residuales que se aceptan y documentan:
- **R1 (A9/A10/A11):** exfiltración pasada irreversible y ventana de `exp` para cert robado. Mitigación: `exp` corto + renovación + `D` no-extraíble. **No** se promete recuperación de datos ya copiados.
- **R2:** revocación no verificable por terceros (la lista vive en el daemon). Mitigación parcial: `exp` corto + scope mínimo. Endpoint público de revocación firmado = mejora futura.
- **R3:** blast radius del iframe `store.` (XSS = device-key de todas las apps). Mitigación: `D` no-extraíble, CSP estricta, allowlist de origin en `postMessage`, scope acotado.

---

## 5. Cambios concretos vs. el diseño/código original

### 5.1 `@dotrino/identity` — `vault/capabilities.js`

- Bajar `DEFAULT_DELEGATION_MS` de 24 h a, p. ej., **1 h** para scopes de lectura/store; mantener `MAX_DELEGATION_MS` como tope duro pero **no** concederlo por defecto.
- Añadir helper `deriveSAS(master, dpub, sn)` → 6 dígitos (HKDF-SHA-256 sobre `canonicalStringify({iss:master, sub:dpub, sn})`, módulo 10^6). Módulo puro, reusable por vault y dispositivo (misma cripto del ecosistema, no se reimplementa nada).
- Exponer `verifyChain`/`verifyDelegation` ya existentes (sin cambios) para que el **dispositivo** valide el cert en el paso 8.

### 5.2 CLI / daemon — `dotrino-vault`

`src/protocol.js` (preferiblemente movido a `@dotrino/identity/vault-protocol.js` y re-exportado para compat):
- Versión de QR `v:2` con campo `sn` (sessionNonce).
- Nuevos mensajes: `MSG.ENROLL_CHALLENGE = 'vault.enroll.challenge'`, `MSG.REVOKED = 'vault.revoked'`.
- `SCOPE` mínimo por defecto: enrolar con `[vault:read]` (o `[vault:store]`); `vault:sign` **solo** con gesto explícito.

`src/vault.js`:
- `startPairing`: scope por defecto **mínimo** (no `[SCOPE.SIGN, SCOPE.READ]`); generar y guardar `sn`; estado `AWAITING_ENROLL`. NO firmar nada aquí.
- `handleEnroll` (reescrito): exigir `data.signature` válida con `dpub` (`rawVerify`), `sn` correcto; calcular `deviceId` + `SAS`; pasar a estado `PENDING_CONFIRM`; responder `ENROLL_CHALLENGE { deviceId, sas }`; **mostrar al dueño en el PC** `deviceId`+`SAS` y esperar `approve`. **No** llamar `signDelegation` hasta la confirmación.
- Nuevo `handleApprove(deviceId)` (vía nuevo comando/Señal): solo entonces `signDelegation(dpub, scopeMínimo, ttlCorto)` y responder `ENROLLED { cert, iss, sas }`.
- Nuevo `emitRevoke(deviceId)`: construir `body={op:'revoke',sub,nonce,iat,exp}`, firmar con la maestra (`identity.signData`), `sendByPubkey(dpub, {MSG.REVOKED, body, sig})` con reintentos.
- `handleGet`: scope acotado a subárbol; rechazar `id:'root'` salvo scope explícito; anti-replay por `data.ts` + ventana.

`src/ctl.js`:
- `pair`: imprimir **solo el QR** por defecto (no el objeto JSON copia-pegable); banner rojo: "Este código autoriza LEER tus datos y FIRMAR con tu identidad. NUNCA lo compartas, ni con soporte. Caduca en N min y sirve una sola vez." Mostrar el `scope` en español llano.
- Nuevo `approve <deviceId>` y `reject <deviceId>`: confirma/rechaza un enroll pendiente (lo que dispara el `signDelegation`). Mostrar el `SAS` para que el usuario lo compare con el del dispositivo.
- `devices`: imprimir el `deviceId` (`sub`) de cada cert (el dato ya está en `devices.json`), no solo `label`/`nonce`. Añadir `revoke --all` / `revoke --all-except <deviceId>`.

`src/daemon.js`:
- SIGUSR1 (`pair`): **no** volcar el token a `pair.json` en claro de forma persistente; mantenerlo en memoria del daemon y entregar al CLI solo lo mínimo y efímero. `startPairing({ label:'cli' })` con scope mínimo.
- Nueva señal/IPC para `approve`/`reject` (mismo patrón de archivo-petición + SIGUSR2 ya usado para `revoke-request.json`).

`src/client.js` (referencia Node + base del navegador):
- `enroll`: firmar `data` con `D` y enviarla en el `ENROLL`; manejar `ENROLL_CHALLENGE` (mostrar SAS/deviceId); al recibir `ENROLLED`, **validar** con `verifyChain({ cert: res.cert, trustedIssuer: qr.iss, expectedSub: device.publickey, expectedScope })` y exigir `res.cert.iss === qr.iss` y `res.cert.sub === device.publickey` **antes** de retornar; **dejar de devolver `res.iss`** (devolver `qr.iss`).
- Nuevo manejador `MSG.REVOKED`: verificar firma de la maestra pineada antes de cualquier acción (en Node solo loguea; en el navegador dispara el self-wipe — §5.4).

### 5.3 `dotrino_profile` (UX de emparejar)

- Pantalla en modo `self`: pegar/escanear el QR `v:2`; mostrar el **fingerprint del `iss`** y, tras enviar el ENROLL, mostrar el **SAS** que devuelve el vault para que el usuario lo **compare** con el del PC antes de aprobar.
- Tres acciones separadas y claramente etiquetadas: **Conectar** (no borra), **Mover identidad a otra bóveda** (borra, con confirmación textual), **Desconectar**.
- Llama `Identity.enrollDevice(qr)` (scope `vault:sign`, on-demand) y `Store.vaultEnroll(qr)` (scope `vault:store`) — cada pilar enrola su propio `D`.

### 5.4 `@dotrino/store` (iframe `store.dotrino.com`)

- `D` generado con `CryptoKey` `extractable:false` en IndexedDB (no exportable) → cierra exfiltración por XSS.
- `vault-backend.js`: en cada `call(op,args)`, identify firmado por `D`, ops cifradas E2E de cara al proxy, validación estricta del cert en enroll (igual que client.js).
- Manejador `MSG.REVOKED`: **self-wipe solo** si la firma valida contra `master` pineado y `sub === D.publickey` y `op === 'revoke'`. Distinguir `expired` (renovar) de `revoked` (wipe). Antes de borrar irreversible: bloquear acceso primero; conservar cache durable hasta confirmar que el último estado se subió (evitar perder cambios no sincronizados).
- IndexedDB siempre cache durable: escrituras offline nunca se pierden; reconciliación idempotente por `id+ts`.

---

Archivos load-bearing a tocar (rutas absolutas):
- `/mnt/sda1/Dotrino/dotrino-vault/src/vault.js` (handleEnroll reescrito + handleApprove + emitRevoke + scope mínimo)
- `/mnt/sda1/Dotrino/dotrino-vault/src/client.js` (prueba de posesión + validación estricta en enroll + MSG.REVOKED)
- `/mnt/sda1/Dotrino/dotrino-vault/src/ctl.js` (approve/reject, devices con deviceId, banner, solo-QR)
- `/mnt/sda1/Dotrino/dotrino-vault/src/daemon.js` (no persistir token, IPC de approve)
- `/mnt/sda1/Dotrino/dotrino-vault/src/protocol.js` → mover a `/mnt/sda1/Dotrino/dotrino-identity/vault/vault-protocol.js` (re-export)
- `/mnt/sda1/Dotrino/dotrino-identity/vault/capabilities.js` (deriveSAS, DEFAULT_DELEGATION_MS más corto)
- `/mnt/sda1/Dotrino/dotrino-identity/vault/core.js` (signData bifurcado, vaultPair/vaultUnpair, MSG.REVOKED self-wipe)
- `/mnt/sda1/Dotrino/dotrino_profile/src/main.js` (UX tres acciones + SAS)
- `/mnt/sda1/Dotrino/dotrino-store/store/` (`vault-backend.js`, `merge.js`, `D` no-extraíble, MSG.REVOKED)

El cambio que cierra el agujero de raíz es la **confirmación humana del `deviceId`+SAS en la máquina de la maestra antes de `signDelegation`** (paso 6-7) combinada con la **validación estricta de la cadena en el dispositivo** (paso 8): el token deja de ser credencial suficiente y la maestra solo firma para el `D` que el usuario aprobó comparando códigos. Todo lo demás es defensa en profundidad.