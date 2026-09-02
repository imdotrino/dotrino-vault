# Modelo de amenazas — el ecosistema Dotrino

> Escrito el 2026-09-02. **Vive en `dotrino-vault` porque aquí está el núcleo** —identidad,
> acta, sellado, secretos—, pero describe el ecosistema entero.
>
> Esto **no es una certificación ni la sustituye**. Es la respuesta a tres preguntas: qué
> hay en juego, quién puede llegar a ello, y **qué NO cubrimos**. La tercera es la que
> importa: un modelo de amenazas que solo enumera lo que protege no sirve para decidir nada.
>
> Cómo reportar un fallo: [`SECURITY.md`](https://github.com/imdotrino/.github/blob/main/SECURITY.md).

## 1. Qué hay en juego

Lo que el ecosistema existe para proteger no es una abstracción; es un inventario:

| | Dónde vive |
|---|---|
| **La identidad del usuario** — la llave con la que firma y con la que es él | en su aparato |
| **Lo que escribe, guarda y comparte** — mensajes, archivos, fotos, dónde está | su almacén, su node |
| **Las credenciales de sus servicios** — tokens, llaves de producción | cajones del vault |
| **Con quién habla y cuándo** | inevitablemente, en el transporte |

Y las llaves que sostienen todo eso, que son el objetivo real de cualquiera que vaya en serio:

| Llave | Para qué | Cerrada con |
|---|---|---|
| **maestra** | sella el acta y regenera sobres. **Nada más** | la contraseña del perfil |
| **`#recovery`** | la envoltura que lleva **todo** sobre: abre cualquier cajón | la contraseña del perfil |
| **`enc-keypair`** | abre el contenido sellado al perfil | la llave de la máquina |
| **de sellado** (`sealkeys`) | firma lo que la bóveda sirve | la llave de la máquina |
| **de comunicación** (`commkey`) | identifica a la bóveda en el proxio | la llave de la máquina |
| **de cada aparato** | firma por ese aparato; el acta dice qué puede | no extraíble (navegador) / archivo cifrado (daemon) |

## 2. Quién puede llegar, por capacidad

Se modela por **lo que alguien puede hacer**, no por quién es. Un actor no es un villano con
nombre: es un conjunto de capacidades, y eso es lo que se puede razonar.

### 2.1. Quien pasa por el transporte (opera el proxio, o está en medio)

**Lo que ve:** que dos llaves se hablan, cuándo y cuánto. El proxio enruta por pubkey y los
aparatos se identifican con un sobre firmado, así que **el grafo social y los horarios son
visibles para quien lo opera**. Y el proxio de producción corre en un VPS alquilado.

**Lo que no ve, si la app cumple:** el contenido. `wrapForMember`/`openWrap` sella los
mensajes dirigidos y el proxio transporta bytes opacos.

**Lo que NO está cerrado hoy, y es lo más importante de este documento:** *el transporte no
cifra por sí mismo.* `sendByPubkey` manda el payload **tal cual**. Solo va sellado si la app
lo sella. Ver §4.1.

### 2.2. Quien tiene el disco (una copia, un respaldo, un portátil robado)

Todo lo del vault va **cifrado en reposo** con una clave derivada de la máquina. Un archivo
suelto copiado a otro equipo no sirve.

**Medido el 2026-09-02, con el perfil cerrado:** la maestra y `#recovery` **no ceden** —se
comprobó descifrándolas con la llave de la máquina y el AES-GCM no autentica—, así que **los
cajones no se abren llevándose el disco**. Sí ceden `enc-keypair`, la de sellado y la de
comunicación (§4.2).

**Y el cifrado en reposo NO protege contra una copia del DISCO ENTERO**, porque su material
vive en ese mismo disco. Sube el listón de «copiar un archivo» a «tener la máquina». Cerrarlo
de verdad exige que la clave no esté ahí: para eso está el proveedor KMS
(`atrest rekey`, [`llaves-de-hardware.md`](./llaves-de-hardware.md)), **implementado y sin usar**.

### 2.3. Quien tiene la máquina (tu usuario, o root)

**No se cubre, y no se puede.** Lee lo mismo que leemos nosotros. Un candado de software no
protege de quien controla el software. Lo que sí hay: los datos en 0600, el directorio 0700,
y la maestra sellada bajo la contraseña — cerrada, **no está en memoria**, así que ni con la
máquina se firma con ella.

### 2.4. Quien tiene un aparato del acta

Aquí manda el acta y solo el acta: qué puede cada miembro lo dice ella, y quitar un aparato
es quitarle la llave. Un papel bien firmado de un aparato que el acta ya no nombra **no
entra** — se comprueba en cada mostrador (`memberCanScope`).

Con un aparato **admin** robado, y el perfil CERRADO, se puede: leer la bitácora, listar
variables y **sobrescribirlas a ciegas** — no leer una privada, pero sí reemplazarla. Y hay
públicas que son endpoints (`CONTENT_S3_ENDPOINT`): reescribir una apunta un servicio a otro
sitio en su siguiente arranque. Queda **auditado con el aparato que lo hizo** y se revoca.
Es deliberado: un admin puede admitir y expulsar, pero **no reescribir quién manda**, así que
el daño es acotado y reversible en vez de un traspaso de mando sin vuelta atrás.

### 2.5. Quien opera un servicio del ecosistema

Un servicio enrolado recibe **sus** secretos y nada más: el acta le da un `cn` y solo abre su
cajón. **No ve el inventario de aparatos del dueño** — no es asunto suyo. Y un `cn` no puede
sobrescribir un sobre existente ni poner uno fuera de su cajón.

### 2.6. Quien mira desde fuera (la web, el registro npm, el catálogo)

Se indexa **la herramienta**, nunca el contenido: lo compartible viaja por `#fragment`, que
no llega al servidor. Sin cookies, sin rastreadores, sin JS de terceros. Los paquetes se
publican desde CI con procedencia firmada, así que se puede comprobar de qué commit salen.

## 3. Lo que se afirma con pruebas, no con adjetivos

Cada invariante tiene un test. Esto es lo que se puede enseñar, no lo que se puede prometer:

| Invariante | Dónde |
|---|---|
| La maestra **no firma** con el perfil cerrado: no está en memoria ni en el disco | `multiprofile.e2e` → *con el profile locked* |
| `unlock` **abre de verdad** o deja el perfil cerrado — nunca «abierto» sin estarlo | `multiprofile.e2e` → *con la maestra sellada, reiniciar…* y *una contraseña MALA…* |
| La llave de comunicación **no recibe sobres**, ni con un cajón llamado como su `cn` | `smoke/reposo` → *un cajón llamado `vault`…* · `llave-de-transporte-sin-sobres` |
| La llave que firma lo servido **no es miembro**: no hay camino por el que reciba nada | `llave-de-transporte-sin-sobres` → *quien firma no está entre quienes reciben* |
| **Nada en claro en el disco**, ni el valor ni la contraseña ni un JWK privado | `smoke/reposo` (9 escenarios) |
| Tocar el pasado de la bitácora **rompe la cadena** y se ve dónde | `bitacora-encadenada` (5 casos, uno afirma la limitación) |
| Un servicio **no ve el inventario** de aparatos | `secrets.e2e` |
| Quien administra **no puede ver un valor a distancia**: la operación no existe | `secrets.e2e` |
| Un sobre con la firma cambiada **no se abre** | `secrets.e2e` |

## 4. Lo que NO se cubre

Esta sección es el motivo por el que el resto del documento vale algo.

### 4.1. El transporte no cifra: hay apps que mandan en claro

`@dotrino/proxy-client` enruta por pubkey y **manda el payload tal cual**. El sellado
(`sendSealed` + `requireSealed`) existe desde 0.13.0 y es obligatorio por norma, pero **la
migración no está terminada**: `messenger`, `vault` y `remote-agent` cifran por su cuenta,
`passmanager` usa el pilar, y **el resto de apps con mensajes dirigidos viaja en claro hoy**.
Quien opere el proxio lo lee. Es deuda abierta y está en `PENDIENTES.md`.

### 4.2. Tres llaves ceden a la llave de la máquina

- **`enc-keypair`** — abre el contenido sellado al perfil. **No abre ningún cajón de
  secretos** (se midió: no hay un solo sobre dirigido a ella). Es la pieza que falta cerrar
  bajo la contraseña, y lo que lo frena es decidir si el almacén sirve con el perfil cerrado.
- **de sellado** y **de comunicación** — ceden **a propósito**: son las que dejan servir y
  hablar con el candado echado. Si pidieran la frase, una bóveda cerrada no existiría en la
  red ni atendería a sus aparatos, que es justo lo que el candado no debe romper. La de
  comunicación va acotada por el acta (`cn: 'vault'`, solo `sign`): habla por la bóveda, no
  firma por la persona ni lee nada.

### 4.3. La bitácora se puede truncar por el final

Está encadenada por hash, así que reescribir o quitar una entrada del medio se ve. **Cortar
el final no**: un prefijo sigue siendo una cadena válida. No se cierra en local — pide anclar
el último hash fuera de la máquina (un TSA, otro aparato). Hay un test que lo afirma, para
que no se descubra el día de una auditoría.

### 4.4. Las llaves del daemon son archivos

En el navegador la privada es una `CryptoKey` **no extraíble**: ni el propio código lee sus
bytes. En el daemon es un JWK cifrado en reposo — atado a la máquina por cifrado, no por
hardware. No hay TPM ni enclave. El KMS de `atrest` es el camino, y está sin usar.

### 4.5. Metadatos del transporte

Quién habla con quién y cuándo es visible para quien opera el proxio. No hay mezcla de
tráfico ni relleno. Cerrar eso es otro problema y no está resuelto.

### 4.6. Ninguna app cuida lo que su dueño decide mostrar

A partir del momento en que alguien comparte algo, manda la decisión y no el código. El
diseño empuja a que compartir sea explícito, reversible y del usuario — nunca una casilla
marcada por defecto— pero no puede deshacer lo compartido.

### 4.7. Lo que nadie ha revisado todavía

**No hay revisión criptográfica externa ni pentest.** Todo lo de arriba lo afirma quien lo
escribió. Es la siguiente cosa que compra credibilidad de verdad, y está en
`CUMPLIMIENTO.md` §3. Tampoco hay certificaciones, auditorías de terceros, SSO ni soporte
24/7: no existen, y no se prometen.

## 5. Cómo se decide aquí

Tres reglas de fondo, porque explican por qué el sistema está hecho así:

- **La maestra tiene dos trabajos y ninguno más**: sellar el acta y regenerar los sobres al
  abrir. Todo lo demás va a otra llave. Cerrada no se firma nada, y **no se regenera**: una
  identidad que se inventa un par nuevo porque no pudo abrir el suyo deja al dueño fuera de
  su cuenta para siempre, y en silencio.
- **Nada de repliegues.** `if (record && !puede())` significa «sin acta, pasa» — y el dato
  falta justo cuando algo se rompió. Si falta lo necesario para decidir, se para y se dice.
- **El acta es la única autoridad de pertenencia.** No hay una segunda lista que acordarse de
  tocar.
