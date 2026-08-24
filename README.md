# Dotrino Vault — tu bóveda personal

> **Parte del ecosistema [Dotrino](https://dotrino.com).** Tu identidad y tu
> contenido, en tu máquina, bajo tus reglas — sin anuncios, sin cookies, sin rastreo.

`dotrino-vault` es la **bóveda personal** del usuario: un **servicio headless** que
corre en tu propia máquina y hace dos cosas.

- **Es tu certificador.** Custodia la llave que manda sobre tu cuenta y actúa como
  tu **propia CA**: enrolas tus dispositivos, firmas por ti y avalas a otras
  personas sin pedirle permiso a ningún portero central. En vez de depender de las
  CAs, del "Inicia sesión con Google/Apple" o de un verificador de KYC, **certificas
  tú**. Esa llave **nunca sale** de la máquina.
- **Es tu almacén.** Guarda el contenido de tus apps —hilos, "recientes", tu
  perfil— **cifrado de punta a punta** con la clave de tu cuenta, y se lo sirve a
  los dispositivos que tú conectaste. El proxy transporta el sobre; no puede
  abrirlo.

**No escucha nada**: no abre puertos ni hay que tocar el router. Se conecta él hacia
afuera al proxy del ecosistema, y tus aparatos lo alcanzan por ahí.

**Este repo publica dos paquetes npm distintos**, con versiones independientes:

| Paquete | Dónde | Qué es |
|---|---|---|
| **`@dotrino/vaultd`** | la raíz | el daemon de este README: `dotrino-vaultd`, la CLI `dotrino-vault`, la TUI y el binario único. |
| **`@dotrino/vault`** | [`lib/`](./lib/) | la librería: usar **este dispositivo (navegador) como bóveda**, sin un PC con el daemon, y el **cliente de servicio** en Node (`/config`, `/env`, `/service`) con su CLI `dotrino-env`. Documentación propia en [`lib/README.md`](./lib/README.md). |

Que las versiones no coincidan es normal: son dos paquetes, no uno.

## Modelo: un perfil es un acta, y una sola llave la sella

**Tres palabras para lo mismo, dicho una vez:** una **cuenta** es un **perfil** es un
**acta** — el conjunto de llaves miembro más la política firmada que dice qué puede
cada una. Un **miembro** es una **llave**, no un aparato: un mismo aparato puede
tener varias llaves y por lo tanto varias cuentas. La TUI llama **bóvedas** a esos
perfiles porque cada uno tiene su llave, su directorio y sus dispositivos; la
**bóveda** a secas es este servicio, que los atiende todos a la vez.

```
 perfil (= cuenta) ── nombre estable: profileId = pubkey de la llave génesis
   └── ACTA firmada: quién es miembro y qué puede cada uno
         · sellador (master): UNA sola llave firma el acta. La intención es que sea la bóveda.
         · miembros: una LLAVE cada uno, con capacidades
             sign · store · read   → un dispositivo tuyo
             secrets + cn          → un servicio: abre SOLO su propio cajón
         · llavero: la clave de contenido del perfil, envuelta para cada miembro

 PC (bóveda)  ── su llave NUNCA sale ──────────────────────────────────────┐
   · sella el acta (si es el master) y emite un CERT por miembro:          │
     "D puede <scope> en nombre de esta llave, hasta <exp>, revocable por <nonce>"
   · firma datos a pedido de un miembro enrolado (devuelve solo la firma)  │
   · abre y cierra el contenido con la clave del perfil                    │
         ▲ proxy (sendByPubkey + cola offline 24 h)                        │
         │                                                                 │
   cel / laptop  ── su propia llave (ninguna otra la ve) ──────────────────┘
     · se empareja con un QR → entra al acta y recibe su cert
     · firma cada acción con su llave y adjunta el cert; la bóveda verifica la cadena
```

**El nombre de la cuenta es el `profileId`**: la pubkey de la llave donde nació, y no
cambia nunca — es lo que conocen la reputación, los contactos y todo lo que esa
cuenta firmó. **No tiene por qué ser la llave de la bóveda**: si la cuenta nació en
tu teléfono y la bóveda la adoptó, la bóveda es la que manda pero el nombre sigue
siendo el de la llave génesis. Lo que la bóveda pone en cada cert es su propia llave
(quien lo emitió), no el nombre de la cuenta.

**Qué autoriza qué, hoy.** Para firmar, leer y guardar, la autorización sale del
**cert** (se verifica la cadena hasta la llave de la bóveda). El **acta** se comprueba
*encima* del cert en los **secretos de servicios**, donde el `cn` del miembro tiene
que decir que es ese servicio: dos cierres independientes, así el límite no depende
solo de qué cert se emitió un día.

```sh
dotrino-vault members            # el acta: qué llaves son tuyas y qué puede hacer cada una
dotrino-vault caps <ID> +firma   # cambia permisos (+firma -guarda +lee +administra +aprueba …)
```

**Los certificados caducan y se renuevan solos.** Un cert dura **30 días**. Mientras
siga vigente y no esté revocado, el dispositivo pide uno fresco por su cuenta —misma
llave, mismos permisos— sin QR ni aprobación. Un cert **vencido o revocado ya no se
renueva**: ahí toca volver a emparejar. Así una máquina que te robaron y revocaste
queda fuera en cuanto expira, sin depender de que ella se porte bien.

**Si se pierde la llave que sella, se pierde la cuenta.** No hay recuperación, ni
relevo, ni frase de respaldo: es la consecuencia asumida de que las llaves no se
copian. Por eso la bóveda **no te deja borrar un perfil que ella manda si quedan
otros dispositivos dentro**: primero le pasas el mando a uno que esté conectado. Si
lo borraras así, los demás se quedarían con su llave y sin nadie que pueda volver a
firmar el acta, y la cuenta moriría para todos sin avisar.

La cripto **no se reimplementa**: vive en `@dotrino/identity` (`signDelegation`,
`verifyChain`, `makeDeviceKey`, más `acta` y `content`) y el transporte es
`@dotrino/proxy-client`. Lo que sí vive aquí es el **lado-bóveda del emparejamiento**
(`lib/src/enroll.js`): un solo sitio donde se decide a quién se le emite un
certificado, compartido por el daemon del PC, por `@dotrino/vault` —que convierte un
navegador en bóveda— y por la copia vendorizada del iframe de identidad.

Diseño completo en [`docs/acta-de-perfil.md`](./docs/acta-de-perfil.md).

### Qué atiende la bóveda

Las peticiones de un dispositivo **ya enrolado** (`sign`, `store`, `get`, `devices`,
`renew`, `secrets`) van firmadas por él y con su certificado; se verifica la cadena,
que el cert no esté revocado y que la hora venga dentro de una ventana de **±5
minutos** (sin eso, un relay podía reproducir mensajes firmados viejos durante toda
la vida del cert). Los del emparejamiento son la excepción, porque ahí todavía no hay
cert: `hello` solo se contesta a quien presente el nonce de una sesión de
emparejamiento viva, y `enroll` va firmado por la llave del dispositivo como prueba
de posesión.

| Mensaje | Qué hace |
|---|---|
| `hello` | entrega la llave de la bóveda a quien presenta el nonce de la invitación corta, firmado |
| `enroll` · `acta.sealed` | los dos caminos de vinculación (entrar a una cuenta / que la bóveda adopte la del aparato) |
| `sign` | la llave firma un payload y devuelve **solo la firma** |
| `store` | el contenido del usuario: hilos, "recientes" y perfil, cifrado de punta a punta |
| `get` | lee un nodo del árbol de contenidos (`vault.json`) |
| `devices` | la lista de dispositivos **más el acta** y la cadena de versiones que le falte |
| `renew` | cert fresco a 30 días, misma llave y mismo scope |
| `secrets` | el bundle de un servicio, sellado a una llave efímera y firmado |

Y emite `revoked` (autoborrado firmado) y `secrets.changed` (aviso de rotación).

Lo que pasa queda anotado en `activity.log` (JSONL, rotado a ~1 MB): qué dispositivo
firmó, renovó o enroló, y qué se rechazó y por qué, **sin el contenido de lo
firmado**. Se lee con `dotrino-vault activity`.

## Instalación

Tres vías, y todas dejan la misma bóveda: **instalador de Linux** (queda como
servicio), **un comando** (`npx`, en cualquier sistema con Node) y **Docker**. En
Linux la primera es la cómoda; en Windows y macOS todavía no hay instalador de un
clic, así que van por las otras dos.

**Ubuntu / Debian — `.deb`:** descarga el `.deb` (versionado) desde
[Releases](https://github.com/imdotrino/dotrino-vault/releases/latest) y haz doble
clic, o en la terminal:

```sh
sudo apt install ./dotrino-vault_*.deb
```

Deja los binarios en `/usr/bin` e instala la unidad `systemd --user` en
`/usr/lib/systemd/user`, habilitada para **todos** los usuarios de la máquina (cada
uno con su propia bóveda en su `$HOME`): te arranca sola en tu **próximo inicio de
sesión**. Para levantarla ya, `systemctl --user start dotrino-vault`; si estabas
**actualizando**, el servicio viejo sigue corriendo y hay que reiniciarlo con
`systemctl --user restart dotrino-vault`.

**Otro Linux x64 con systemd — tarball:**

```sh
tar xzf dotrino-vault-*-linux-x64.tar.gz
cd dotrino-vault-*-linux-x64
sh install.sh
```

Hace lo equivalente en tu `$HOME` (`~/.local/bin` + `~/.config/systemd/user`) y va un
paso más allá: lo **arranca en el acto** y activa `linger`, así el vault corre desde
el arranque de la máquina aunque no inicies sesión.

El binario del tarball y el `.deb` son **x64/amd64** y el instalador **necesita
systemd** (si no lo encuentra, se detiene y te dice cómo arrancar el daemon a mano).
Para ARM —una Raspberry— o para un Linux sin systemd, usa Docker o `npx`.

Ambos traen **Node embebido**: no necesitas instalar Node ni dependencias de npm. Lo
único que esperan del sistema es `libatomic1`, que casi todas las distribuciones
traen puesta; el `.deb` la declara y la instala sola si falta. Con el tarball, en un
sistema muy pelado (un contenedor mínimo), instálala tú: `sudo apt install
libatomic1`.

**Cualquier sistema con Node — un comando:**

```sh
npx -y @dotrino/vaultd          # Node ≥ 20
npx -y @dotrino/vaultd --tui    # la bóveda y su pantalla de control en la misma ventana
```

Es la vía normal en **Windows y macOS**, y sirve igual en Linux. Arranca en primer
plano: la bóveda vive mientras dejes esa ventana abierta. Los comandos de control se
anteponen con `npx -p @dotrino/vaultd` (por ejemplo, `npx -p @dotrino/vaultd
dotrino-vault pair`). Si no tienes Node, el instalador del ecosistema lo baja en tu
carpeta, sin permisos de administrador, y corre el paquete:

```sh
# Linux y macOS
curl -fsSL https://install.dotrino.com/install.sh | sh -s -- @dotrino/vaultd
# Windows (PowerShell)
& ([scriptblock]::Create((irm https://install.dotrino.com/install.ps1))) @dotrino/vaultd
```

**Docker (cualquier sistema, y la única vía *empaquetada* para ARM — el `.deb` y el
tarball son solo x64; `npx` también sirve en una Raspberry):**

```sh
docker volume create dotrino-vault
docker run -d --name dotrino-vault --restart unless-stopped \
  -v dotrino-vault:/data ghcr.io/imdotrino/dotrino-vault

docker exec -it dotrino-vault dotrino-vault pair   # conectar un aparato
```

La imagen se publica en GHCR en cada versión, para amd64 y arm64 (una Raspberry
encendida en casa es el caso normal, no el exótico). No abre ningún puerto y el CLI
entra por `docker exec` porque le habla al daemon por archivos del dir de datos, no
por un socket. **El volumen ES tu cuenta:** si lo borras, esa identidad no se
recupera.

> Sin firma de código: tu sistema puede advertir que el binario no está firmado. Es
> autohospedado y de código abierto; en Linux solo necesita permiso de ejecución (el
> instalador lo da). Hay un build de Windows (`packaging/build-win.sh`) pero **no se
> publica**: se construye desde Linux y no se ha probado en un Windows de verdad, y
> la inyección del blob invalida la firma de Microsoft, así que saltaría SmartScreen.

**Dónde vive todo y cómo se para.** Tus datos —llave incluida— viven en
`~/.local/share/dotrino/vault` (Linux y macOS), `%LOCALAPPDATA%\Dotrino\vault`
(Windows) o `/data` dentro del volumen (Docker), siempre con permisos `0600`/`0700` y
un subdirectorio `p/<id>/` por perfil. Se mueve con `DOTRINO_VAULT_DIR`. Arrancar y
parar depende de cómo lo instalaste: `systemctl --user {start,stop,restart}
dotrino-vault`, `docker restart dotrino-vault`, o cerrar la ventana del `npx` y
volver a correrlo. El propio CLI te dice cuál te toca cuando el daemon no está.

### CLI de control

```sh
dotrino-vault tui                  # interfaz de terminal a pantalla completa (ver abajo)
dotrino-vault status               # estado del servicio + fingerprint
dotrino-vault pair                 # empareja: muestra el QR (más la URL y un código pegable) y espera
dotrino-vault pair --new-account [nombre]   # estrena una cuenta VACÍA aquí y mete al dispositivo en ELLA
dotrino-vault pair --adopt [nombre]         # al revés: la bóveda se queda con la cuenta que trae el aparato
dotrino-vault pair --save [archivo]         # además, escribe la invitación en un .dpair para llevarla
dotrino-vault pending              # qué dispositivo está esperando (su identificador) y cómo aprobarlo
dotrino-vault approve <código>     # aprueba tecleando los 6 dígitos que MUESTRA el dispositivo
dotrino-vault reject  <deviceId>   # rechaza un dispositivo pendiente
dotrino-vault devices              # lista dispositivos enrolados / revocados
dotrino-vault members              # el acta del perfil: qué llaves son tuyas y qué puede cada una
dotrino-vault caps <ID> ±permiso   # cambia lo que puede un dispositivo (+firma -guarda +lee +administra +aprueba …)
dotrino-vault revoke  <nonce>      # revoca un dispositivo (le ordena autoborrarse)
dotrino-vault activity [n]         # bitácora de seguridad: firmas, renovaciones, enrolados, rechazos
dotrino-vault pair --service <ns>  # empareja un SERVICIO (proxy, geo…) con acceso SOLO a sus secretos
dotrino-vault pair --scope <lista>  # los PERMISOS del cert: sign,read,store,secrets:<ns>. Sin esto, sign,read,store.
dotrino-vault caps <ID> +permiso     # ese aparato pide tu aprobación (teléfono) al recibir claves; pair --approval al enrolar
                                    # Se combina con --service: `--service eco --scope sign` = un bot que firma
                                    # como aparato del acta y lee SOLO su cajón. `admin` no se empareja (caps).
dotrino-vault secret set <ns> <CLAVE> <valor>   # variable del SCOPE: la comparten todos los
                                                # aparatos que sirven ese namespace
dotrino-vault secret set <ns> CLAVE=valor CLAVE2=valor2 …   # VARIAS de una vez (un solo aviso)
dotrino-vault secret import <ns> [archivo.env]  # lo mismo desde un .env (o por la entrada estándar)
dotrino-vault secret rm  <ns> <CLAVE>           # borra una variable del scope
dotrino-vault secret device set <ID> <CLAVE> <valor>   # variable de UN aparato: solo la lee él
dotrino-vault secret device set <ID> CLAVE=valor …     # varias de una vez
dotrino-vault secret device import <ID> [archivo.env]
dotrino-vault secret device rm  <ID> <CLAVE>           # borra una variable de ese aparato
dotrino-vault secret list                       # los dos cajones, por nombre (nunca valores)
dotrino-vault logs                 # últimas 40 líneas del servicio (journalctl; solo donde hay systemd)
dotrino-vault version              # versión instalada (status avisa si el daemon quedó viejo)
```

`approve` recibe el **código**, no el `deviceId`: la bóveda no conoce el código —solo
su compromiso— y lo aprende cuando lo tecleas. El que sí recibe `deviceId` es
`reject`.

El `ns` de un secreto va en minúsculas (`[a-z0-9-]`, hasta 32), la clave en
MAYÚSCULAS_CON_GUION_BAJO (hasta 64) y el valor es texto de hasta 8 KB.

#### Cargar la configuración de un servicio: JUNTA, no de una en una

Guardar una variable hace que la bóveda **avise al servicio de que su configuración
cambió**, y el servicio **sale** para que su supervisor lo levante y la lea entera y
fresca (`watchEnv`, más abajo). Cargándolas de una en una, seis variables son **seis
avisos**: el servicio obedece el primero y arranca con lo que hubiera puesto en ese
momento mientras tú sigues escribiendo el resto — configuración a medias, y encima
parece que funcionó.

Por eso cargar configuración es **una sola orden**:

```sh
dotrino-vault secret import proxy .env             # el .env que ya tienes
cat .env | dotrino-vault secret import proxy       # o por la entrada estándar
dotrino-vault secret set proxy TURN_KEY_ID=k-123 DB_URL=postgres://…   # o a mano, juntas
```

Se leen `CLAVE=valor` (comentarios con `#`, `export` delante, comillas alrededor del
valor). **Todo o nada**: si una línea está mal, no se guarda ninguna y se dice cuál —
media configuración aplicada es peor que ninguna. Un `#` **a mitad de línea no corta el
valor** (una contraseña puede llevarlo), y una clave repetida es un error, no «gana la
última».

Lo mismo desde la **TUI** (tecla `i` en Variables) y desde la **consola remota**, donde
se edita todo lo que haga falta y se confirma con **un solo botón**.

#### Las variables de entorno se ponen en DOS SITIOS

| Dónde | Quién la lee | Para qué |
|---|---|---|
| **Por scope** — `secret set <ns> …` | todos los aparatos del perfil que sirven ese namespace | lo que es igual lo corra quien lo corra: la llave de la API, la URL de la base |
| **Por aparato** — `secret device set <ID> …` | solo ese aparato | lo que cambia de máquina a máquina: el puerto, la URL pública, el nombre del nodo |

Al servicio se le entrega **un solo bundle**: el del scope con el suyo **encima**. Si
una variable está en los dos, **manda la del aparato** — lo específico gana, igual que
un `.env` de máquina sobre el general. Así dos servidores sirven el mismo `ns` sin
tener que partirlo en `proxy-1` y `proxy-2` para cambiar un puerto.

Lo del aparato se indexa por su llave, que es la misma que firma la petición: no hay
forma de pedir lo de otro. Solo se le pueden poner a un **servicio** (un miembro con
nombre de servicio en el acta): un teléfono no pide bundles, así que guardárselas sería
configuración muerta. Y **al quitar el aparato se van con él**.

#### Pública o privada: si el VALOR puede salir de esta máquina

Cada variable, esté en el cajón que esté, es **pública** o **privada**, y eso decide una
sola cosa: si su valor puede viajar hacia la **consola remota** (`vault.dotrino.com`, un
aparato tuyo con permiso de administrar). Al servicio que la lee le da igual: recibe las
dos.

```sh
dotrino-vault secret set web PUBLIC_URL https://ejemplo.com --public
dotrino-vault secret set web API_KEY sk-…              # sin bandera: privada
dotrino-vault secret visibility web PUBLIC_URL private # taparla sin tocar el valor (privada → pública no existe)
```

- **Se nace privada.** Y **rotar el valor conserva la visibilidad**: exponer un secreto
  tiene que ser una decisión, no el efecto colateral de un `set`.
- Desde la consola remota se ve el **nombre** de todas y el **valor solo de las públicas**;
  a cualquiera se le puede poner un valor nuevo **a ciegas** (rotar una llave que no puedes
  leer es justo para lo que sirve), y **borrar** no se delega. Lo que viaja va **cifrado**
  con la clave de contenido del perfil: el proxy no ve nada. Detalle y límites en
  [`docs/consola-remota.md`](./docs/consola-remota.md).

### Interfaz de terminal (TUI)

Las bóvedas, los dispositivos y los secretos también se manejan desde una **interfaz
de terminal a pantalla completa**, sin memorizar subcomandos. El acta (`members`,
`caps`) y la bitácora (`activity`) todavía no están ahí: para eso, la CLI.

```sh
dotrino-vault tui             # binario instalado
dotrino-vaultd --tui          # la bóveda y su interfaz en la MISMA ventana
                              # (si ya hay una corriendo, se engancha a ella)
node bin/dotrino-vault-tui.js # en desarrollo  (o:  npm run tui)
```

Como la CLI, la TUI **no abre la identidad ni la red**: le deja la orden al daemon en
un archivo del dir de datos (la señal es solo para que la atienda al instante; el
daemon vigila la carpeta igual, porque en Windows no hay señales). El daemon debe
estar corriendo; si no, la TUI ofrece arrancarlo con `S` — solo sabe hacerlo por
systemd, así que en Docker o fuera de Linux arráncalo tú.

**Navegación en dos niveles**, para que siempre sea explícito de qué bóveda son los
dispositivos/variables que estás viendo:

1. **Bóvedas** es la pantalla de entrada: lista tus perfiles (`↑↓` mover, `Enter`
   **entrar** a uno — lo activa si no lo estaba). Ahí también **conectas un
   dispositivo** con `p` (sin entrar: activa la bóveda elegida y abre la pregunta de
   a qué cuenta entra), creas una bóveda nueva, renombras, borras y pones/quitas/usas
   la contraseña (candado).
2. Al entrar caes en sus **pestañas horizontales**, que cambias con `←→`:
   - **Dispositivos (pares):** verlos, **emparejar** uno nuevo, **aprobar** con el
     código que muestra el dispositivo, **rechazar** y **revocar**.
   - **Scopes y variables (secretos):** ver los scopes y sus variables (nunca los
     valores), **agregar** una variable (con su scope) y **quitar** una variable o un
     scope entero. Son las **compartidas**: las de UN aparato se ponen en la otra
     pestaña, y esta lo dice en vez de repetirlas.

   Y dentro de **Dispositivos**, con `e` sobre un servicio, sus **variables propias**:
   las que lee solo él y le ganan a las del scope que se llamen igual. Cada cajón se
   administra donde ya elegiste lo que lo distingue — el namespace en su pestaña, el
   aparato en la lista de aparatos. En los dos, `t` cambia si la variable es **pública**
     (su valor se puede ver desde la consola remota) o **privada**.

Al emparejar, la bóveda **pregunta primero a qué cuenta entra el dispositivo** y
recién después muestra el QR, que además dice de qué cuenta salió. Se responde de tres
formas: entrar a la cuenta activa, estrenar una nueva, o **conectar un servicio**
(pide el namespace —`proxy`, `geo`…— y emite la invitación con scope
`vault:secrets:<ns>`, igual que `pair --service`; el QR avisa de que lo que entrega es
un servicio y no un aparato del dueño). Es lo que hace falta para que ese aparato
luego tenga variables propias: sin `cn`, la bóveda no se las guarda. Una cuarta
opción, «adoptar la cuenta que trae el dispositivo», aparece **desactivada**: el
dispositivo todavía no sabe entregar la suya. Desde la CLI ese camino ya se inicia con
`dotrino-vault pair --adopt`.

`Esc` desde las pestañas vuelve a la lista de bóvedas; `q` sale desde cualquier
pantalla, salvo mientras escribes en un campo o respondes una confirmación: ahí se
sale con `Esc` o `Ctrl+C`.

**Idioma (`l`).** La TUI está en **español e inglés** y la tecla `l` conmuta entre los
dos en cualquier pantalla (incluida la de "el daemon no está corriendo"). El idioma
se recuerda en `prefs.json` del dir de datos, y al arrancar se decide en este orden:
`DOTRINO_LANG` (si la pones, manda en esa ejecución) → `prefs.json` → el locale del
sistema (`LC_ALL`, `LC_MESSAGES`, `LANGUAGE` o `LANG`) → español.

**Las teclas NO cambian con el idioma**: son mnemónicos en **inglés** y valen igual en
español (solo se traduce la palabra que las explica en la barra de ayuda).

| Tecla | Acción | Dónde |
|---|---|---|
| `Enter` | open — entrar a la bóveda | Bóvedas |
| `n` | new — bóveda nueva / variable nueva | Bóvedas · Scopes |
| `r` | rename (Bóvedas) · refresh (Dispositivos/Scopes) · restart (Emparejar) | — |
| `d` | delete — borrar la bóveda | Bóvedas |
| `p` | **pair — conectar un dispositivo** (desde Bóvedas entra directo, sin `Enter`) | Bóvedas · Dispositivos |
| `c` | change password — poner/cambiar la contraseña | Bóvedas |
| `x` | quitar: contraseña · dispositivo pendiente · variable/scope | Bóvedas · Dispositivos · Scopes · Emparejar |
| `u` / `k` | unlock / locK — candado de la bóveda | Bóvedas |
| `a` | approve — aprobar el dispositivo | Dispositivos · Emparejar |
| `v` | reVoke — revocar un dispositivo enrolado | Dispositivos |
| `y` | yes — confirmar (también se acepta `s`) | confirmaciones |
| `n` / `Esc` / `Enter` | no — cancelar la confirmación | confirmaciones |
| `Supr` | lo mismo que `d` (Bóvedas), `v` (Dispositivos) y `x` (Scopes) | listas |
| `RePág` `AvPág` `Inicio` `Fin` | mover de 5 en 5 · ir al principio o al final (en Emparejar, scroll del QR) | listas |
| `Ctrl+U` / `Ctrl+W` | limpiar el campo / borrar la última palabra | al escribir |
| `b` / `Esc` | back — volver | pestañas · Emparejar · ¿a qué cuenta entra? |
| `S` / `R` | arrancar el servicio / volver a comprobarlo | daemon detenido |
| `l` | language — español ⇄ English | todas |
| `q` | quit — salir | todas |

### Varios perfiles en el mismo PC

Puedes tener varias identidades tuyas en la misma máquina (p. ej. personal y
trabajo). Cada perfil es **una cuenta distinta**: su propia llave, sus propios
dispositivos, sus propios datos y secretos — nada se cruza entre ellos. **Todos
atienden a la vez**: el perfil «activo» solo decide a cuál va un comando cuando no lo
dices con `--profile`, no apaga a los demás.

```sh
dotrino-vault profile ls                  # lista los perfiles (* = el activo)
dotrino-vault profile add Trabajo         # crea un perfil (identidad nueva, vacía)
dotrino-vault profile use Trabajo         # elige el activo
dotrino-vault profile rename <nombre>     # renombra
dotrino-vault profile rm Trabajo          # BORRA el perfil y su identidad (te pide escribir su nombre)

dotrino-vault pair --profile Trabajo      # cualquier comando acepta --profile (o -p), en cualquier posición
dotrino-vault devices --profile personal  # vale el id o el nombre (sin distinguir mayúsculas)
```

No se borra el único perfil, ni una cuenta que manda esta bóveda mientras le queden
otros dispositivos: primero le pasas el mando a uno conectado.

Si ya usabas el vault antes de esto, tu identidad de siempre se convierte sola en el
primer perfil («Perfil 1»): la misma llave, los mismos dispositivos, nada que volver
a emparejar.

### Contraseña del perfil (opcional) — el candado es de ESTA CONSOLA

Cada perfil puede llevar contraseña. Con el perfil **bloqueado**, desde la máquina de la
bóveda no se puede **ver ni tocar nada suyo**: ni sus dispositivos, ni sus variables, ni
el acta, ni tus datos, ni la bitácora — y tampoco emparejar, aprobar, quitar o guardar
una variable. La CLI y la TUI contestan «bóveda bloqueada» hasta que alguien teclee la
contraseña.

Lo que **no** cambia es el servicio: **tus dispositivos ya emparejados siguen firmando,
leyendo y guardando** aunque esté bloqueado. Eso viaja por el proxy, no por esta consola,
y así un reinicio del PC nunca deja tus apps muertas esperando a que alguien teclee algo.

```sh
dotrino-vault profile password     # pone o cambia la contraseña (te la pregunta)
dotrino-vault profile password rm  # la quita
dotrino-vault unlock               # abre la bóveda en esta consola
dotrino-vault lock                 # vuelve a cerrarla
```

Lo único que se sigue viendo con el candado puesto es que **existe** y que está cerrada
(`status`, `profile ls`): si no, no habría forma de saber qué abrir.

El perfil se vuelve a bloquear al reiniciar el servicio. La contraseña **no se
guarda**: solo un verificador con sal (PBKDF2), igual que el candado del navegador.
Tiene un mínimo de 4 caracteres y, tras 5 intentos fallidos, cada intento nuevo
espera cada vez más (hasta 5 minutos); la cuenta de fallos se guarda, así que
reiniciar no la borra.

Con el perfil bloqueado, la CLI **no** te pide la contraseña sobre la marcha: cualquier
comando que mire o toque esa bóveda falla con «perfil bloqueado» y hay que correr
`dotrino-vault unlock` antes. La TUI sí la pide sola: al **entrar** a una bóveda cerrada
(y antes de enseñar nada) te pregunta la contraseña.

Para que quede claro qué protege y qué no. **Protege la consola**: que otro que se siente
en tu máquina vea o toque lo que hay en esa bóveda. **No** cifra la llave en el disco —de
eso se encarga el cifrado en reposo, más abajo, que hoy no usa la contraseña—, así que
alguien con acceso a esta máquina como tu usuario o como root sigue pudiendo leer los
archivos por su cuenta. Es un candado de la puerta por la que se administra, no una
imposibilidad criptográfica.

## Emparejar un aparato

**Vincular tiene exactamente dos caminos, y pregunta la bóveda antes de enseñar el
QR:**

- **El aparato entra a una cuenta de la bóveda** — la que elijas, o una nueva que se
  estrena para él (`pair --new-account`). El aparato estrena una llave; nada de lo que
  ya tenía se sobrescribe.
- **La bóveda adopta la cuenta del aparato** (`pair --adopt`): la cuenta sigue siendo
  la misma para todo el mundo —el mismo `profileId`, la misma reputación— y lo que
  cambia es quién sella. El aparato se queda como un miembro más.

**No existe fusionar dos cuentas**, ni al vincular ni después. El modo viaja dentro de
la invitación, el dispositivo lo repite firmado y la bóveda rechaza el que no coincida
con el que abrió. Detalle en
[`docs/vinculacion-de-cuentas.md`](./docs/vinculacion-de-cuentas.md).

**Emparejamiento endurecido.** El dispositivo prueba posesión de su llave firmando el
enrolamiento, y la bóveda solo firma el certificado **después** de que teclees el
**código de 6 dígitos que muestra el dispositivo**. El código no viaja: el dispositivo
lo sortea, lo enseña en su pantalla y manda solo su **compromiso**
`SHA-256(código‖llave‖sesión)`. La bóveda no lo conoce —no lo puede mostrar ni
comparar por su cuenta—; lo aprende cuando lo tecleas, recompone el compromiso y solo
si coincide firma el certificado. Aprobar exige, entonces, haber ido a leer la
pantalla del dispositivo. Al entregar el certificado la bóveda devuelve el código, y
el dispositivo lo rechaza si no es el suyo: una bóveda falsa, que nunca lo vio, no
puede enrolarlo. Un código robado ya no alcanza para entrar, y la revocación de un
dispositivo le ordena **autoborrarse** (con firma de la llave que manda, no por un
mensaje cualquiera).

> El porqué y las amenazas que cierra están en
> [`docs/pairing-protocol.md`](./docs/pairing-protocol.md). Ojo: ese documento es la
> decisión de diseño original y en dos puntos quedó atrás del código — el código de
> aprobación lo genera el dispositivo, no lo deriva la bóveda, y se aprueba
> tecleándolo, no comparándolo en dos pantallas.

**La cita del proxy.** Lo que va en el QR no es la dirección de la bóveda: es una
**cita** que emite el proxy — 6 caracteres, un solo uso, 5 minutos de vida; los 2
primeros dicen qué proxy la emitió, para poder canjearla desde otro nodo. El
dispositivo la canjea, obtiene la dirección real de la conexión y recién entonces le
pregunta a la bóveda quién es, presentando el nonce de la sesión; la respuesta va
firmada y con ese nonce dentro de lo firmado, así que no sirve la de otro
emparejamiento. Se gana doble: el QR no deja impresa ninguna dirección permanente, y
la dirección de verdad —34 caracteres, para poder rutearse entre proxies— no tiene que
caber en un código que se dicta.

La invitación viaja **comprimida** (`lib/src/invite.js`) y tiene dos formas. La que se
emite hoy es la **corta**: 21 caracteres, un enlace de 51, porque no lleva la llave ni
el nombre de la cuenta. Eso deja el QR en 29 módulos, que en la terminal son **39×20**.
Si el proxy no sabe emitir citas, la bóveda cae sola a la forma **compacta**: 91
caracteres, enlace de 121 y un QR de 41 módulos (51×26). Ahí sí viaja la llave, y el
grueso del ahorro es ella: va el **punto comprimido** de la curva (33 bytes) y el
lector rearma la JWK con una plantilla, comprobando que sale **byte a byte** igual,
porque el proxy direcciona por esa string exacta. Si una llave no encaja en ninguna
plantilla, la invitación sale en su forma larga (base64 del JSON): se hace grande,
nunca incorrecta. Las tres formas son una sola palabra en base64url, así que el mismo
texto sirve para el QR y para pegar.

## Lo que guardas: el store del usuario

Un dispositivo enrolado con el permiso de guardar (`vault:store`) usa la bóveda como
su almacén: **hilos** de contenido (agregar, listar, borrar, exportar/importar), el
contador de **aperturas** que alimenta los "recientes" del hub, y tu **perfil** (apodo,
avatar, campos), del que la bóveda es la copia autoritativa — cada dispositivo lo
empuja al editarlo y lo jala al arrancar, así que ves el mismo perfil en todos.
Espeja el modelo de datos de `@dotrino/store`, guardado en `threads.json` dentro del
dir del perfil. Las lecturas se conforman con `vault:read`; escribir exige
`vault:store`.

El contenido que guardan las apps viaja **cifrado de punta a punta** con la clave de
contenido de tu perfil: el dispositivo cifra antes de enviar y la bóveda responde
cifrada con la misma clave. El proxy transporta el sobre pero no puede leerlo. Si
esta bóveda no tiene la clave de contenido del perfil, rechaza la operación en vez de
guardar en claro.

La excepción, dicha sin adornos: la sincronización del **perfil**
(`profileSet`/`profileGet`) todavía viaja **sin cifrar**, y una operación que llegue
en claro se guarda en claro. Es deuda, no diseño.

El candado de contraseña cierra **esta consola** (ver arriba): guardar y leer contenido
desde tus dispositivos siguen funcionando con el perfil bloqueado.

(El otro store, el «árbol de contenidos» de `vault.json`, es hoy un esqueleto: se
puede leer con `vault.get`, pero ningún mensaje del protocolo escribe nodos.)

## Cifrado en reposo

**Todo** lo que la bóveda guarda va **cifrado** con AES-256-GCM y una clave derivada de
material de **esta máquina** (`/etc/machine-id` en Linux, `MachineGuid` en Windows,
`IOPlatformUUID` en macOS) más un salt local: `identity.json` (la maestra),
`vault.json` (el árbol de contenido), `threads.json` (hilos, aperturas y tu perfil) y
`secrets.json` (los secretos de servicios). Copiar cualquiera de esos archivos a otro
equipo **no sirve de nada**.

En la máquina del **servicio** pasa lo mismo con `service-identity.json`
(`@dotrino/vault/env`), que lleva la llave privada de su dispositivo.

La migración es sola y sin pedir nada: un archivo de una instalación anterior se lee
igual estando en claro y queda cifrado en la primera escritura (la identidad se migra
al arrancar, verificando que puede volver a leerse antes de reemplazar el original).
Queda fuera a propósito `activity.log`, la bitácora de auditoría: no guarda payloads
(solo op, dispositivo y hora) y se quiere legible para diagnosticar.

Lo que **no** resuelve, dicho sin adornos: no protege contra alguien con acceso a esta
misma máquina como tu usuario o como root — puede leer el mismo material que leemos
nosotros. Es subir el listón (de «copiar un archivo» a «tener tu máquina»), no una
imposibilidad criptográfica. Y hoy la **contraseña del perfil no participa** en esa
clave, aunque `machineKey` ya la acepta. Todos los archivos conservan además sus
permisos `0600` dentro de un dir `0700`.

## Desarrollo

```sh
npm install                          # Node ≥ 20
node bin/dotrino-vaultd.js           # arranca el daemon (modo servicio)
node bin/dotrino-vaultd.js --pair    # arranca + imprime un QR de emparejamiento
node bin/dotrino-vaultd.js --tui     # la bóveda y su pantalla de control, misma ventana
npm test                             # 118 pruebas (node --test, sin dependencias)

bash packaging/build.sh              # binario único SEA + tarball de Linux (dist/)
bash packaging/build-deb.sh          # el .deb (requiere dpkg-deb; construye el binario si falta)
bash packaging/build-win.sh          # .exe + .zip de Windows, cruzado desde Linux (sin probar)
docker build -t dotrino-vault .      # la imagen (la misma que CI publica en GHCR)
```

Los tests cubren lo que duele si se rompe: el emparejamiento y la comprobación del
código antes de firmar, la compresión de la invitación, el cifrado en reposo, el
aislamiento entre perfiles, el freno de borrado del acta, los secretos de punta a
punta y la precedencia del vault sobre el `.env`; también el render y el bilingüe de
la TUI. **Tres son de extremo a extremo contra el proxy de verdad** y esperan el repo
hermano en `../dotrino-proxy` (`secrets.e2e`, `multiprofile.e2e`,
`pairing-cita.e2e`): no se saltan solos, así que sin ese repo al lado `npm test`
falla.

Etiquetar `vaultd-v<ver>` publica la imagen de Docker en GHCR; el `.deb` y el tarball
se suben a la release a mano.

### Enrolar y usar desde un dispositivo (Node, para testing)

```js
import { enroll, requestSign } from './src/client.js'

// 1) lees la invitación LARGA del vault → { iss, proxy, token, sn }
//    (este helper es solo para pruebas: no sabe canjear la cita de la invitación
//     corta. Ese camino lo implementan `lib/src/service.js` y `@dotrino/identity`.)
const { device, cert, iss } = await enroll({
  qr,
  onChallenge: ({ deviceId, code }) => console.log(deviceId, '→ teclea en el vault:', code)
})   // GUARDA device (privada) + cert

// 2) le pides a la bóveda que firme algo (su llave nunca sale)
const { signature } = await requestSign({
  masterPubkey: iss, proxyUrl: qr.proxy, device, cert,
  payload: { hola: 'mundo' }
})
```

## Secretos de servicios

Los servicios del ecosistema (proxy, geo, bots…) **no llevan secretos de terceros en
su `.env`**: se enrolan a la bóveda como un miembro más, con un cert limitado al scope
`vault:secrets:<ns>` y un `cn` que el acta reconoce, y al arrancar piden su bundle.
Esto es la cara Node del paquete hermano **`@dotrino/vault`**; la documentación
completa está en [`lib/README.md`](./lib/README.md).

Son **dos momentos distintos, a propósito**: el **enrolamiento** es un comando previo
que corre un humano **una sola vez** por máquina; el **arranque** solo lee la
identidad ya guardada y no interactúa con nadie.

```bash
# en el VAULT (tu PC)
dotrino-vault pair --service proxy                 # invitación con scope SOLO vault:secrets:proxy
dotrino-vault secret set proxy TURN_KEY_ID  …

# en la MÁQUINA del servicio (pega la invitación; te MUESTRA un código)
npx -p @dotrino/vault dotrino-env enroll --ns proxy    # el bin vive en @dotrino/vault

# de vuelta en el VAULT: tecleas los 6 dígitos LEYÉNDOLOS de la pantalla del servicio
dotrino-vault approve 418027
```

Deja `~/.dotrino/service/<ns>/service-identity.json` (0600) con la llave del
dispositivo (generada ahí, nunca sale) + el cert. **En la máquina del servicio no
queda ningún secreto**: los valores viven solo en memoria del proceso. En la
**bóveda** sí quedan en disco (`secrets.json`, 0600, en claro). Un agente tiene **una
sola** identidad y se la cede el vault: volver a enrolar **reemplaza** la anterior, que
es la forma de rotar la de un agente comprometido.

**Por qué NO se enrola en el primer arranque de la app:** el enrolamiento exige un
humano que **lea el código en la pantalla del servicio** — es lo único que impide que
una bóveda falsa (que nunca vio el código) enrole la máquina. Un servicio arranca bajo
systemd/PM2, sin TTY y sin nadie mirando: el código acabaría en un log. Separados, el
arranque es determinista e idempotente: solo **lee**; el enrolamiento **escribe** y
consume una invitación de un solo uso.

```js
import '@dotrino/vault/config'     // como `dotenv/config`, pero contra el vault
                                   // ns: DOTRINO_NS, o el único enrolado en la máquina
console.log(process.env.TURN_KEY_ID)
```

**Precedencia — el vault MANDA** (desde `@dotrino/vault` 0.14.0): lo que venga del
vault **pisa** el `.env` y el entorno. No lo reemplaza (el `.env` sigue arrancando
cualquier máquina sin enrolar), pero tiene la última palabra sobre las claves que
administra. Es lo que hace barata la **rotación**: se cambia en un solo lugar y ningún
`.env` rancio olvidado en un VPS puede seguir ganando.

**Al rotar, el agente SE REINICIA.** Cuando guardas o borras un secreto, la bóveda
manda a los agentes de ese `ns` un aviso **firmado** —sin valores— y agrupa las
escrituras seguidas para que cargar cinco variables no provoque cinco reinicios. El
agente **no recarga en caliente: termina**, y lo levanta su supervisor. Así que **el
servicio tiene que correr bajo pm2 o systemd con `Restart=always`**: sin supervisor, la
primera rotación lo deja apagado. Sale en vez de recargar porque en JavaScript un
secreto no se puede borrar de la memoria (los strings son inmutables, no hay
`zeroize`) y una llave se rota casi siempre *porque se filtró*: un proceso nuevo
empieza con el heap limpio.

**Y no se fía del aviso: al conectar, COMPARA.** Un aviso es un mensaje, y los mensajes
se pierden. Si el agente está vivo pero incomunicado —se cayó el proxio, se fue la red—
el aviso se le encola; si el corte pasa de **5 minutos** lo descarta al llegar (ventana
de frescura) y si pasa de **24 h** ni llega (caduca en la cola). Antes ahí se acababa:
al reconectar volvía a *escuchar*, nunca preguntaba, y se quedaba con la configuración
vieja para siempre mientras el log decía «ignorado» como si estuviera bien. Ahora, en
**cada conexión**, el agente pide su bundle y compara la huella con la que tiene
aplicada; si no coincide, reacciona igual que con el aviso. El aviso sigue siendo el
camino rápido —de segundos—; la comparación es el que no se pierde. Cubre también los
avisos que el propio agente descarta por la gracia de arranque o el piso entre avisos, y
la **revocación** que ocurrió mientras estaba incomunicado (la comparación recibe *no
autorizado: revoked* y lo apaga). Comparar tiene su propio piso —`reconcileMinMs`, 30 s—
para que una conexión que va y viene no le pida el bundle a la bóveda cada cinco
segundos.

**Y no puede volverse un ciclo de reinicios.** Lo que se compara son **dos bundles de la
bóveda**, nunca el `.env` contra el bundle: la referencia es lo que el agente recibió, así
que *recibir la configuración por primera vez* —tarde, que es como la recibe el proxio—
no es un cambio. Encima, un reinicio por comparación no puede repetirse más de una vez
por **gracia de arranque**: dentro de esos 30 s la comparación **se aplaza** (a
diferencia del aviso, que ahí sí se descarta), de modo que ni un fallo sistemático
lograría más de un reinicio cada 30 s — tiempo de sobra para que el supervisor lo marque
como inestable en vez de que la máquina se pase el día arrancando.

**Modos de fallo:**

- **Vault caído / proxy caído** → **espera** (reintento con backoff, para siempre).
  Esperar al vault es la **regla**: arrancar igual sería operar con la configuración
  vieja del `.env`, que es justo lo que el vault vino a dejar de ser. La **única**
  excepción es el **proxio**, y no por importancia sino por estructura: el vault habla
  con sus servicios *por* el proxio, así que un proxio que lo espera espera a alguien
  que necesita el proxio escuchando. Para ese caso está `applyEnv`.
- **Sin enrolar, cert revocado o vencido, scope equivocado, o un acta que no reconoce
  a ese miembro como el servicio `<ns>`** → **aborta en el acto**. No se arreglan
  reintentando: hay que (re)enrolar. El cert del servicio vive 30 días y se renueva
  **al pedir los secretos** —o sea, al arrancar— cuando le quedan menos de 7: no hay
  temporizador. Así que «vencido» pasa tanto si el agente estuvo apagado más de un mes
  como si estuvo encendido más de un mes sin reiniciarse.

Revocar el cert corta el acceso: la bóveda emite un `REVOKED` **firmado** y el agente
que está a la escucha se apaga en el acto y no vuelve. Un agente sin escucha
(`DOTRINO_ENV_WATCH=0`, o `applyEnv` a secas) conserva en memoria lo que ya había leído
hasta que alguien lo reinicie.

| Variable | Para qué |
|---|---|
| `DOTRINO_NS` | namespace de secretos; si falta, el único enrolado en la máquina |
| `DOTRINO_ENV_OVERRIDE=0` | por esta corrida, gana el entorno (el vault deja de pisar) |
| `DOTRINO_ENV_WATCH=0` | no escuchar avisos de cambio (el proceso no termina al rotar) |
| `DOTRINO_ENV_DIR` | dónde está `service-identity.json` de ese ns |
| `DOTRINO_ENV_HOME` | raíz de las identidades de servicio (por defecto `~/.dotrino/service`) |
| `DOTRINO_ENV_QUIET=1` | no imprimir la línea de arranque |

CLI de apoyo: `dotrino-env status` (qué hay enrolado aquí), `dotrino-env check` (los
**nombres** de los secretos, nunca los valores), `dotrino-env run -- <cmd>` (inyecta
los secretos en el entorno de un proceso que no es Node). Primer consumidor:
`dotrino-proxy` (TURN de Cloudflare).

### Aprobación desde el teléfono (un aparato que pide permiso para recibir claves)

Liberar claves privadas a un aparato puede exigir el **visto bueno de otro aparato** (el
teléfono, con `caps <ID> +aprueba`). Es una propiedad **del aparato**, no del cajón: el VPS
desatendido no pide; la PC del dueño sí. Por defecto nadie pide; se fija al enrolar o se
cambia después como un permiso más:

```sh
dotrino-vault caps <ID-del-teléfono> +aprueba        # quién aprueba (no viaja en un QR)
dotrino-vault pair --service claude --approval       # el que entre pedirá permiso
dotrino-vault caps <ID> +permiso | -permiso          # cambiarlo después
dotrino-env run --ns claude -- node mi-script.js     # el proceso espera el sí…
```

…la bóveda apunta el pedido, avisa al teléfono (cola del proxio → aviso nativo en la app de
Dotrino), y solo su firma entrega las claves — **al proceso que pidió, en memoria**. Pide en
**cada petición**, que para un servicio bien hecho es **una por arranque**: pide al iniciar,
se queda las claves en memoria y no vuelve a pedir. Lo denegado corta sin reintentos; lo que
nadie atiende vence a los 5 min; todo queda en `dotrino-vault activity`.

### La llave SSH como un secreto más (`dotrino-env ssh-agent`)

La llave privada SSH vive **sellada en la bóveda** (cajón `ssh`, variables `SSH_KEY_*` con el
archivo en base64) y solo existe en claro en la memoria del agente que la pidió. En el disco
de la PC no queda nada; cerrar el agente es olvidar las llaves.

```sh
dotrino-vault secret set ssh SSH_KEY_DOTRINO "$(base64 -w0 ~/.ssh/id_ed25519)"
dotrino-env enroll --ns ssh --code <código>                 # una vez (pair --service ssh --approval en la bóveda)
dotrino-env ssh-agent --ns ssh              # pide el cajón (tu sí en el teléfono) e imprime export SSH_AUTH_SOCK=…
ssh mi-servidor                             # firma en local, con la llave en memoria
```

ed25519 en formato OpenSSH (sin frase: la bóveda es el candado) y RSA/P-256 en PEM.

## Alcance

- **v1 (este):** daemon headless en Node, **multi-perfil**. En **Linux** queda como
  servicio `systemd --user` (binario único Node SEA: `.deb` y tarball); en **Windows y
  macOS** se corre con `npx`, en primer plano; y en cualquier sistema, con **Docker**
  (imagen amd64/arm64 en GHCR). Identidad **cifrada en reposo y ligada a esta
  máquina**. Emparejamiento endurecido con los dos caminos de vinculación, acta del
  perfil (miembros, capacidades y `cn` de servicio), firma delegada, renovación
  automática del cert a los 30 días, store de hilos/aperturas/perfil **cifrado de punta
  a punta**, secretos de servicios sellados a una llave efímera, y bitácora de
  actividad. Contraseña opcional por perfil, **para editarlo** (verificador PBKDF2).
- **v2:** cifrado en reposo **con la contraseña del perfil** (hoy la clave sale solo de
  la máquina) y atado a tu cuenta del sistema —DPAPI en Windows, Keychain en macOS— o
  al TPM; cifrar también los secretos y el store; **instalador de un clic para Windows
  y macOS**; UI de escritorio (Tauri) como cliente del daemon; firma de documentos con
  sellado de tiempo (`dotrino-signer`).

## Estructura

- `src/vault.js` — núcleo de UN perfil: identidad + transporte + el router de mensajes.
- `src/profiles.js` — registro multi-perfil (`profiles.json`, `p/<id>/`) + candado por contraseña.
- `src/manager.js` — corre todos los perfiles a la vez (uno por llave/conexión) y aplica el freno de borrado.
- `src/daemon.js` — modo servicio: `state.json`, control por archivos + señales, apagado limpio.
- `src/ctl.js` — CLI de control (habla con el daemon por archivos + señales, sin socket).
- `src/vaultControl.js` — API de control programática (misma vía que la CLI); la usa la TUI.
- `src/tui/` — interfaz de terminal, sin dependencias (`term.js` primitivas ANSI/raw-mode; `app.js` pantallas; `i18n.js` los textos es/en).
- `src/transport.js` — conexión headless al proxy + `identify` firmado (con el acta).
- `src/threadStore.js` — el store del usuario: hilos, "recientes" y perfil (`threads.json`).
- `src/store.js` — árbol de contenidos (`vault.json`, versionado). Hoy es un esqueleto: se lee, nadie escribe.
- `src/secretsStore.js` — secretos por namespace de servicio (`secrets.json`), validados.
- `src/atrest.js` — cifrado en reposo de la identidad, ligado a esta máquina.
- `src/client.js` — helper de **dispositivo** (enrolar / pedir firma / leer), para pruebas.
- `src/version.js` — de dónde sale la versión (binario SEA / npm / repo), para que `status` avise si el daemon quedó viejo.
- `src/node-globals.js` — los globals de navegador que los paquetes del ecosistema esperan al correr headless.
- `src/protocol.js` — re-export de `lib/src/protocol.js`, la **fuente única** de tipos de mensaje y scopes.
- `src/qr.js` — QR ASCII. · `src/paths.js` — dirs de datos por sistema.
- `lib/` — el paquete npm **`@dotrino/vault`** (bóveda en el navegador + cliente de servicio `dotrino-env`), versionado y publicado **aparte** de la raíz. Dentro: `enroll.js` (el lado-bóveda del emparejamiento, compartido), `invite.js` (la invitación), `service.js`/`env.js`/`config.js`, `sealed.js`, `protocol.js`.
- `bin/sea-entry.js` — entrypoint del binario único (multicall daemon / `--ctl` / `--tui`).
- `bin/dotrino-vault.js` — el CLI de control instalado por npm. · `bin/dotrino-vaultd.js` y `bin/dotrino-vault-tui.js` — entrypoints de desarrollo.
- `vendor/qrcode-generator.cjs` — el encoder de QR vendorizado (MIT): nada de JS de terceros en runtime.
- `packaging/` — `build.sh` (binario SEA + tarball), `build-deb.sh`, `build-win.sh`, `install.sh`/`uninstall.sh`, unit systemd.
- `Dockerfile` — la imagen que publica `.github/workflows/docker.yml` en GHCR.
- `test/` — las pruebas (`npm test`, `node --test`, sin dependencias).
- `web/` — `vault.dotrino.com` (Vite + Vue): la página pública **y la consola «Dónde vive tu perfil»**, la única pantalla del ecosistema donde se ven y gestionan los dispositivos de un perfil. Sirve además las rutas del QR (`/d` y `/dispositivos`). La publica `.github/workflows/deploy.yml`.
- `docs/` — las decisiones de diseño, que mandan sobre el código:
  - [`acta-de-perfil.md`](./docs/acta-de-perfil.md) — el modelo vigente: un perfil es un conjunto de llaves con un acta firmada por un solo sellador.
  - [`pairing-protocol.md`](./docs/pairing-protocol.md) — el emparejamiento endurecido: por qué el token dejó de ser autoridad suficiente.
  - [`vinculacion-de-cuentas.md`](./docs/vinculacion-de-cuentas.md) — los dos caminos al conectar un aparato, y por qué no existe fusionar cuentas.
  - [`store-identity-architecture.md`](./docs/store-identity-architecture.md) — por qué la bóveda del PC hace de store además de identidad.

Sin anuncios, sin cuentas, sin rastreo. MIT · parte de Dotrino.
