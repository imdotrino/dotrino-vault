# Secretos sellados por destinatario

> Diseño acordado el 2026-08-17. **No implementado.** Nace de una pregunta
> concreta: el vault corre en un VPS alquilado, y el dueño de esa máquina puede
> leer el disco. ¿Qué se hace al respecto?

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

Falta una pieza para poder hacerlo: **el aparato no tiene hoy una llave ECDH
duradera**. Su llave de dispositivo es ECDSA, solo firma — por eso `sealed.js`
tiene que inventar una efímera en cada petición. Hay que registrar una ECDH
estable **al enrolar**, y publicarla en el acta como parte del miembro.

Lo que sí existe y se reusa tal cual:

- `lib/src/sealed.js` — ECDH P-256 + AES-256-GCM (`seal`, `openSealed`).
- `@dotrino/identity` — `getEncryptionPubkey()` y `encrypt(recipients, plaintext)`,
  que ya devuelve un sobre multi-destinatario `{ v, iv, ct, wrap }`: **una llave de
  contenido, envuelta una vez por destinatario**. Es exactamente la forma que
  necesita el cajón `ns`, que comparten todos los aparatos de un namespace, y
  hace barata la rotación (se re-envuelve el wrap, no se re-cifra el contenido).

El cajón `dev` ya se indexa por la `pub` del miembro (`secretsStore.js`), así que
ahí el destinatario ya está identificado.

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

En el store son dos cosas distintas — `schemaVersion` 4:

```
secrets.json
  ns:  { <ns>:  { KEY: { sealed: <sobre multi-destinatario>, pub: false } } }
  dev: { <pub>: { KEY: { sealed: <sobre>,                    pub: false } } }
  master: <blob cifrado con la contraseña>   ← solo para re-sellar
```

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

## 4. Hallazgos que hay que arreglar CON esto

Salieron al revisar el código para este diseño. Los tres son precondiciones, no
mejoras opcionales.

### 4.1. `atrest.js` promete una protección que no existe

Su cabecera dice que la clave de reposo mezcla «la contraseña del perfil, si la
hay». **Ningún llamante la pasa**: los cinco —`src/store.js:33`,
`src/secretsStore.js:63`, `src/vault.js:52`, `src/threadStore.js:30`,
`lib/src/service.js:185`— invocan `atRestFor(dir)` a secas. Y no podría ser de otro
modo hoy sin romper que los agentes reciban secretos con el perfil bloqueado.

Corregir el comentario. Un comentario que promete seguridad que no está puesta es
peor que ninguno.

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

Qué hacer:

- **Quitar el verificador** cuando la contraseña sea material de llave: que la
  prueba de que es correcta sea el tag AES-GCM del propio sobre. No elimina el
  ataque fuera de línea —el sobre también es un oráculo— pero obliga a pasar por
  **scrypt** (`N=16384`, ~16 MB, duro con memoria) en vez de por PBKDF2-SHA256,
  que es lo que una GPU come rápido.
- **Cifrar `profiles.json`** como todo lo demás, aunque contra quien tiene el disco
  entero sea cosmético: deja de ser la excepción rara.

### 4.3. El mínimo de contraseña son 4 caracteres

`profiles.js:239`. Razonable para un tope de velocidad; nada contra alguien con el
disco y una GPU. Si la contraseña pasa a proteger secretos de producción, hay que
**pedir frase, no contraseña**, y subir el mínimo en consecuencia.

## 5. Alcance del cambio

- `@dotrino/identity` — ECDH duradera **por aparato** (hoy solo hay por perfil,
  `getEncryptionPubkey`), publicada en el acta al enrolar.
- `lib/src/enroll.js` — registrar esa llave; re-sellar lo del `ns` para el miembro
  nuevo (pide contraseña).
- `src/vault.js` — `var.set` / `var.setMany` sellan a los destinatarios;
  `handleSecrets` deja de re-sellar y reenvía el sobre guardado (sigue firmando el
  cuerpo con la maestra, que es lo que da la autenticidad).
- `src/secretsStore.js` — `schemaVersion` 4, cajón `master` bajo contraseña.
- `src/profiles.js` — derivación de llave por operación y borrado tras usarla;
  §4.2 y §4.3.
- `lib/src/admin.js` + consola — pedir la contraseña al enrolar; avisar cuando el
  perfil no tiene.

## 6. Decisiones abiertas

1. **¿Merece la pena?** Depende de qué perfiles tiene hoy ese VPS. Si solo hay una
   maestra de infraestructura sobre secretos rotables, el trabajo puede no pagarse
   y basta con acotar y rotar (ver `memoria: confianza en el VPS`). Si está la
   maestra personal, lo primero no es esto: es sacarla de ahí.
2. **Rotar el `ns`**: re-envolver el wrap por miembro es barato, pero hay que
   decidir si un aparato revocado obliga a rotar el contenido o solo a quitarle el
   wrap. Quitar el wrap no le retira lo que ya leyó.
3. **Migración** de lo que hoy está guardado en claro: un re-sellado en el primer
   desbloqueo, con la verificación-antes-de-reemplazar que ya usa `migrateFile()`.
