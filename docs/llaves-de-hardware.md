# Llaves de hardware y KMS

> Anotado el 2026-08-30, a raíz de comparar la bóveda con un KMS. **La brecha más
> grande frente a un KMS no se cierra con código: es la raíz de confianza en
> hardware.**
>
> **La costura YA ESTÁ (0.55, 2026-08-30)** — ver §0. El resto de niveles sigue sin
> implementar, pero ahora cada uno es un módulo pequeño en vez de una cirugía.

## 0. Lo que ya existe: el proveedor de KEK

`lib/src/kek.js`. De dónde sale la clave que cifra el disco es **configurable por
perfil**, con dos proveedores:

| Proveedor | Qué hace | Por defecto |
|---|---|---|
| `machine` | scrypt(material de la máquina + salt) — **lo de siempre** | **sí** |
| `command` | envuelve una DEK aleatoria llamando a un programa externo | no |

Con `command` vale **cualquier KMS** —AWS, OpenBao, gcloud, el del cliente, un
script propio— sin meter un SDK en el binario. Contrato del programa: **base64 por
la entrada, base64 por la salida**, y nada más.

**Es por perfil, no por bóveda.** Cada perfil vive en `<vault>/p/<id>` y lleva ahí
su `atrest.json`, así que en la misma máquina un perfil puede ir con KMS y el de
al lado con la clave de siempre. Tumbar el KMS deja mudo **solo** al que depende de
él. (El **registro de perfiles**, en la raíz, tiene su propia clave y **no** queda
cubierto por el KMS de un perfil: guarda la lista y el verificador del candado, no
el contenido de nadie, pero conviene no creer que ya está protegido. `atrest status`
lo avisa.)

```
dotrino-vault atrest status              de dónde sale la clave, perfil por perfil
dotrino-vault atrest test                ¿responde el KMS? sin tocar los datos
dotrino-vault atrest rekey <config.json> cambia de proveedor recifrando todo
dotrino-vault atrest rekey --machine     vuelve a la clave de esta máquina
```

**Editar `atrest.json` a mano está bloqueado a propósito**: estrenar una DEK sobre
datos ya cifrados los dejaría ilegibles para siempre — la maestra incluida — y sin
un solo aviso. Quien lo intente se lleva un `kek-needs-rekey` y ni un byte tocado.
Cambiar de proveedor es `atrest rekey`, que descifra todo con la clave vieja, lo
recifra con la nueva, comprueba archivo por archivo y deja copias `.bak-rekey`.

Y la regla que no se toca: **si el proveedor falla, esto revienta.** No hay
repliegue a `machine`. Un repliegue silencioso convertiría «tumbo la red del vault»
en «el vault se cifra con la clave débil», que es un agujero disfrazado de
comodidad.

### Recetas

**AWS KMS** — `kms-wrap.sh` y `kms-unwrap.sh`:

```sh
#!/bin/sh
# wrap: entra la DEK en base64, sale el sobre en base64
set -eu
base64 -d | aws kms encrypt --key-id "$DOTRINO_KMS_KEY" \
  --plaintext fileb:///dev/stdin --query CiphertextBlob --output text
```

```sh
#!/bin/sh
# unwrap: entra el sobre en base64, sale la DEK en base64
set -eu
base64 -d | aws kms decrypt --ciphertext-blob fileb:///dev/stdin \
  --query Plaintext --output text
```

**OpenBao / HashiCorp Vault (motor transit)** — autohospedado, sin tercero:

```sh
#!/bin/sh
set -eu
bao write -field=ciphertext transit/encrypt/dotrino-vault plaintext="$(cat)" | base64 -w0
```

```sh
#!/bin/sh
set -eu
bao write -field=plaintext transit/decrypt/dotrino-vault ciphertext="$(base64 -d)"
```

Y el `atrest.json` que los usa:

```json
{
  "provider": "command",
  "label": "AWS KMS alias/dotrino-vault",
  "wrap":   { "cmd": "/opt/dotrino/kms-wrap.sh" },
  "unwrap": { "cmd": "/opt/dotrino/kms-unwrap.sh" }
}
```

**Antes de aplicarlo**: `atrest test` con esa config comprueba el ida y vuelta sin
tocar un solo dato. Correrlo primero no es una recomendación, es el orden.

## 1. El hueco, dicho sin adornos

Hoy el cifrado en reposo deriva su clave de `/etc/machine-id` (o `MachineGuid` /
`IOPlatformUUID`) más un salt local, y **los dos viven en el mismo disco que los
datos**. La cabecera de `lib/src/atrest.js` ya lo dice: sube el listón de «copiar
un archivo» a «tener tu máquina», y **no protege contra una copia del disco
entero** — que es exactamente el caso de un vault en un VPS alquilado.

Un HSM cierra ese hueco porque los bytes de la llave **se generan y se quedan
dentro del chip**: no hay operación que los exporte. Quien se lleva el disco no se
lleva nada reutilizable. Y no hace falta un datacenter: el TPM ya está soldado a
casi cualquier PC de los últimos años, y una YubiKey cuesta unos 50 USD.

## 2. El principio de diseño: primero la KEK, nunca la maestra

**Contra la tentación de meter la maestra en el chip a la primera.** D6 dice que
perder el master es perder la cuenta, y `acta-de-perfil.md` §F5 ya advierte que
ligar a hardware **sube la apuesta**: un cambio de placa o de disco mata el perfil.

Por eso el orden es al revés de lo intuitivo:

| | Qué se mete en hardware | Qué se gana | Qué se arriesga |
|---|---|---|---|
| **Primero** | la **KEK** que cifra el disco (`atrest`) | una copia del disco deja de servir | **nada**: las 24 palabras siguen siendo la recuperación |
| **Después, opt-in** | la **maestra** misma (PKCS#11) | la llave no existe fuera del chip, nunca | perder el chip = perder la cuenta; obliga a un segundo chip de repuesto |

La primera fila se lleva casi todo el beneficio con cero riesgo nuevo. Es la que
hay que construir. La segunda es para quien lo pida a sabiendas.

## 3. La escalera, por coste

### Nivel 0 — La contraseña del perfil (ya está el parámetro, nadie lo pasa)

`machineKey(dir, password)` **acepta** una contraseña y **ningún llamante se la
da**. No es un descuido: el candado es de la consola, y un perfil bloqueado tiene
que seguir sirviendo a sus agentes — no podría si sus datos pidieran una frase que
no está puesta.

**Salida:** un **cajón aparte** que solo haga falta al *administrar*, cifrado con
la frase, mientras lo que sirven los agentes sigue con la clave de máquina. Es lo
que la propia cabecera de `atrest.js` propone. Barato y no rompe nada.

### Nivel 1 — El llavero del sistema (ata a la CUENTA, no a la máquina)

| Sistema | Herramienta | Sin módulos nativos |
|---|---|---|
| Windows | **DPAPI** (`ProtectedData`, vía PowerShell) | sí |
| macOS | **Keychain** (`security add-generic-password`) | sí |
| Linux escritorio | **libsecret** (`secret-tool`) | sí |
| Linux headless (VPS) | — no hay llavero de sesión | va al nivel 3 |

Se invocan las herramientas del propio sistema, así que **no rompen el binario
único**. Ganancia: otro usuario de la misma máquina deja de poder leer la KEK.
Sigue sin cubrir a root.

### Nivel 2 — FIDO2 `hmac-secret` / WebAuthn PRF · **la mejor relación coste/beneficio**

Una llave FIDO2 (YubiKey, Nitrokey, SoloKey) con la extensión `hmac-secret`
devuelve `HMAC(secreto-de-la-credencial, salt)` — 32 bytes deterministas que
**solo se obtienen con la llave física presente** y tocada. Eso es exactamente una
KEK: envuelve la clave de `atrest` y listo.

Por qué esta es la buena:

- **Funciona en los dos lados del ecosistema.** En el navegador es la extensión
  **PRF** de WebAuthn, nativa y sin dependencias. En el daemon es **libfido2**
  (`fido2-assert`, o un binding). Un solo concepto para la PWA y para Node.
- Es lo que ya usan Bitwarden y 1Password para el desbloqueo por hardware: camino
  trillado, no invento nuestro.
- **La recuperación no se rompe**: la llave física es *una* forma de abrir la KEK,
  y las 24 palabras siguen siendo la otra.
- Cuesta 50 USD y se puede registrar una segunda de repuesto desde el día uno.

### Nivel 3 — TPM 2.0 (para el VPS, sin interacción humana)

`tpm2_create` sella la KEK bajo la SRK: solo **ese** TPM la abre. Es la única vía
para una máquina headless que arranca sola, donde no hay nadie para tocar una
llave USB.

Dos matices que hay que decir en voz alta:

- **Sin política de PCR**, protege contra el robo del disco pero **no contra root
  local**: cualquier proceso de esa máquina puede pedir el desellado.
- **Con política de PCR** protege además contra arrancar otro sistema, pero **se
  rompe en cada actualización de kernel o de firmware** y hay que re-sellar. Para
  un VPS que se actualiza solo, eso es una avería programada.

Recomendación: TPM **sin** PCR en el VPS (el objetivo ahí es la instantánea del
disco, que es el riesgo real y documentado), y decirlo tal cual en la copy.

### Nivel 4 — PKCS#11: la maestra dentro de la YubiKey (opt-in, avanzado)

Los slots PIV de una YubiKey hacen **ECC P-256**, que es justo la curva del acta,
y hacen tanto **ECDSA** (firmar el acta y los certs) como **ECDH** (abrir el
contenido del perfil). La llave se genera en la tarjeta y no sale.

Esto es literalmente lo que hace un KMS. Y tiene su precio, que no se puede
esconder:

- **Las 24 palabras dejan de recuperar la maestra**, porque ya no hay bytes que
  escribir en ningún sitio.
- Obliga a **enrolar un segundo chip** como sellador de repuesto antes de activar
  el modo. Sin eso, perder el llavero es perder el perfil, y ya está.
- Cada firma pide la tarjeta presente. Para el PC del dueño está bien; para un
  servicio desatendido, no.

### Nivel 5 — El teléfono, que ya existe · **la victoria más barata**

`dotrino-app` ya sostiene `+aprueba`. Meter esa llave en **Android Keystore con
StrongBox** (`setUserAuthenticationRequired`, huella) o en el **Secure Enclave** de
iOS es hardware de verdad, y **no hay que comprar nada ni escribir criptografía
nueva**: es una bandera al generar la llave.

Con eso, la aprobación por uso pasa a estar respaldada por hardware, que es la
propiedad que un KMS **no** te da de forma nativa.

### Nivel 6 — Conectar la bóveda a un KMS (y la costura que lo ordena todo)

> Propuesto por el dueño el 2026-08-30, mientras se escribía este documento.
> **Es mejor idea que la escalera de arriba**, y la reordena entera.
> **CONSTRUIDO el mismo día** — ver §0; lo que sigue es el porqué.

Un KMS **es** un HSM al que se le habla por red. Si el problema es que no tenemos
raíz de hardware, la vía más rápida no es comprar un chip: es **envolver la KEK con
una llave que vive en un HSM ajeno** — el patrón de cifrado de sobre de toda la
vida:

1. Se genera una DEK aleatoria local (la que cifra los archivos, como hoy).
2. Se envuelve llamando a `Encrypt` del KMS. En el disco queda **solo el sobre**.
3. Al arrancar, un `Decrypt` la abre. La DEK vive en RAM y nunca toca el disco.

Ganancias inmediatas: **una instantánea del disco no sirve para nada**, el acceso
se revoca al instante quitando el permiso, y queda **registro de cada apertura**
— tres cosas que hoy no tenemos. Y a diferencia de la FIDO2, **funciona en una
máquina headless que arranca sola**, que era justo el hueco del VPS.

#### Pero un KMS de nube contradice el posicionamiento, y hay que decirlo

Si la bóveda no arranca sin llamar a Amazon, entonces **Amazon puede impedir que
arranque**: cuenta suspendida, caída de región, un fallo de facturación. Se cambia
«me roban el disco» por «dependo de un proveedor», que es exactamente lo que
Dotrino existe para evitar. Y *«soberanía de la información on premise»* deja de
sostenerse en una conversación técnica.

#### La salida: un KMS no es una sola cosa

| Sabor | Hardware | Soberanía | Cuándo |
|---|---|---|---|
| **Nube ajena** (AWS/GCP/Azure KMS) | excelente | **mala**: la raíz es de otro | nunca por defecto; sí si el **cliente** lo pide |
| **Autohospedado** (**OpenBao**, Transit de HashiCorp) sobre TPM o YubiHSM | buena | **tuya** | el VPS del vault, y el on-premise de Enterprise |
| **YubiHSM 2** por PKCS#11 (~650 USD) | HSM de verdad | **tuya** | cuando haya presupuesto |
| **El KMS del cliente** | la que él tenga | **suya, que es lo que quiere** | Enterprise |

#### Y la costura, que es lo que de verdad hay que construir

Hoy `atrest.js` tiene **una** forma cableada de conseguir su clave. Lo que hay que
hacer no es elegir un KMS: es convertir eso en un **proveedor de KEK** con dos
únicas operaciones, `wrap(dek)` y `unwrap(sobre)`, y varias implementaciones
intercambiables:

```
machine (hoy) · password · fido2 · tpm · pkcs11 · kms-openbao · kms-aws · kms-<del-cliente>
```

Con esa costura puesta, todo lo demás es un módulo pequeño y ninguna decisión
queda cerrada. El PC del dueño usa FIDO2, el VPS usa TPM u OpenBao, y **un cliente
de Enterprise enchufa el suyo** — que es literalmente lo que pide un comprador
corporativo (lo llaman BYOK o *external key store*): sus llaves, bajo la gestión de
llaves que ya tiene.

#### Lo que esto le hace al argumento de venta

Le da la vuelta. **El KMS y la bóveda no compiten: se apilan.**

> El KMS guarda **una** llave. La bóveda hace lo que un KMS no hace: identidad,
> pertenencia por acta firmada, revocación por llave, sellado por destinatario y
> aprobación desde el teléfono.

*«Dotrino se conecta al KMS que ya tienes»* es una frase mucho más fuerte que
*«Dotrino tiene su propio esquema»*, y además desactiva la objeción del HSM en vez
de encajarla.

#### ¿Y la maestra dentro del KMS?

Se puede: AWS KMS hace `ECC_NIST_P256` con `SIGN_VERIFY`, así que sellar el acta
sería un `kms:Sign`. Cada sellado pasa a ser un viaje por red y una petición
facturada — tolerable, porque sellar es **administrativo y raro** (servir sobres,
que es lo frecuente, no toca la maestra). A cambio se pierde la exportación, y con
ella **las 24 palabras dejan de recuperar nada**.

Veredicto: **no por defecto en un perfil personal; sí como opción de Enterprise**,
donde el cliente ya tiene KMS, ya tiene su propio proceso de recuperación y
prefiere eso a un papel impreso.

## 4. Orden propuesto

**Primero la costura (nivel 6), y después da igual el orden.** Mientras `atrest.js`
tenga una sola forma cableada de conseguir su clave, cada nivel es una cirugía; con
el proveedor de KEK puesto, cada uno es un módulo de cien líneas que se enchufa.

1. ~~**La costura**: proveedor de KEK (`wrap`/`unwrap`).~~ **HECHO** (§0), con
   `machine` y `command` funcionando y 12 pruebas.
2. **Nivel 5** (teléfono, StrongBox) — casi gratis, la app ya está.
3. **Nivel 2** (FIDO2/PRF) para el PC del dueño — el salto grande.
4. **Nivel 3** (TPM sin PCR) **u OpenBao autohospedado** para el VPS del vault —
   cierra la instantánea del disco, que es el riesgo documentado y real.
5. **Nivel 6 con el KMS del cliente**, cuando lo pida un comprador de Enterprise.
6. **Nivel 0/1** como relleno donde toque.
7. **Nivel 4** solo si alguien lo pide, y con el segundo chip como requisito.

## 5. Estado

**La costura está (§0); los niveles, no.** `machine` sigue siendo el proveedor por
defecto de todos los perfiles, así que **mientras nadie configure un KMS, la brecha
sigue exactamente igual de abierta**: la costura hace posible cerrarla, no la cierra.

Lo que se puede decir hoy en la copy de Enterprise, y nada más: **la bóveda se
conecta al KMS que el cliente ya tenga**. Lo que NO se puede decir: que la bóveda
tenga raíz de confianza en hardware por defecto, porque no la tiene.

`acta-de-perfil.md` §F5 ya listaba «TPM 2.0 opt-in» como pendiente; este documento
lo ordena y añade el resto.
