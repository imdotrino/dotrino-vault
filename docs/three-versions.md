# Las tres versiones del vault: un solo núcleo

> **Estado: 2026-11-04.** vaultd 0.191.0 · `@dotrino/vault` 0.119.0 · `@dotrino/identity` 0.135.1
> (iframe de `id.dotrino.com` con el núcleo 0.119.0) · extensión 0.59.0 (núcleo 0.119.0; antes
> 0.58.3 con el 0.106.0). Revisión anterior: 2026-10-16. Regla del dueño (2026-09-17): el vault existe **siempre** en tres
> versiones —la **pestaña**, la **extensión** y el **binario**—, **compatibles y con las mismas
> funciones**, salvo lo que limita su contexto; **el binario es la fuente de verdad**.
>
> Desde vaultd 0.156.0 / `@dotrino/vault` 0.86.0 / `@dotrino/identity` 0.116.0 las tres corren
> **el mismo código**: el núcleo del demonio (`lib/src/core/vault.js`). Antes la pestaña y la
> extensión corrían un mostrador aparte (`startDeviceVault`, 500 líneas) que atendía la mitad
> del protocolo. El inventario anterior (2026-09-17) está en el historial de este archivo.

## Cómo está hecho

El núcleo recibe todo lo que depende de dónde corre en una **plataforma**:

| | Binario | Pestaña | Extensión |
|---|---|---|---|
| Dónde corre | el demonio `dotrino-vault` | el iframe de `id.dotrino.com`, en la pestaña visible con «este dispositivo es bóveda» | la pestaña de bóveda (`vault-tab.html`) |
| Plataforma | `src/platform.js` | `lib/src/browser.js` (`startBrowserVault`) | la misma, desde `extension/src/logins.js` |
| Disco | archivos 0600 cifrados con la llave de la máquina (`src/disk.js`) | IndexedDB cifrado con una llave AES no extraíble, uno por perfil (`lib/src/core/browserDisk.js`) | igual que la pestaña |
| Identidad | `Identity` sobre su directorio, maestra sellada con la contraseña | el core del iframe, envuelto con `IdentityFacade` | el core del service worker, por mensaje (ninguna llave privada cruza) |
| `/proc` y mostrador local | sí | no: lo declarado se queda como declarado | no |
| OPAQUE | el del paquete | el del paquete | inyectado desde la página sandbox (su CSP no deja WASM) |
| Contraseñas | el núcleo las atiende | el núcleo las atiende | las atiende el worker (único escritor de su almacén) con la **política del núcleo** |

Dos piezas cierran el círculo:

- **La consola en el mismo navegador administra su bóveda por un camino local**
  (`registerLocalVault` en `@dotrino/identity/remote.js`, `core.setSelfVault`): el MISMO
  protocolo de la consola remota (`vault.admin`, `vault.secrets`, `vault.devices`), con la
  misma firma y el mismo certificado, sin proxio. Así `vault.dotrino.com/vault` enseña
  cajones, bloqueados y la lista de aparatos con dónde corre cada uno, igual que contra el
  binario. Para eso la llave de la cuenta se da `admin` a sí misma al arrancar la bóveda
  (queda a la vista en el acta); `aprueba` no, porque haría esperar a los servicios.
- **Una bóveda escribe.** En la extensión, el gestor administra los inicios de sesión
  pidiéndoselo a la pestaña de bóveda por un canal entre páginas; sin la pestaña abierta, se
  dice (`not-the-vault`). Es lo mismo que el binario: `logins add` pide el demonio encendido.

## El binario en los tres sistemas, y su ventana

El binario no es solo de Linux. Es el mismo núcleo y el mismo ejecutable (Node SEA) en
**Linux** (`.deb`, `.rpm`, tarball), **Windows** (instalador por usuario, `build-win.sh`) y
**macOS** (`Dotrino Vault.app` universal, `build-mac.sh`). Lo que cambia por sistema está en
`src/service.js`: cómo se arranca y cómo arranca solo al iniciar sesión (systemd, la entrada
`Run` de Windows, un LaunchAgent). No es una cuarta bóveda: es la del binario.

Su pantalla de control existe en dos formas que son **una sola**: la TUI y **la ventana**
(`desktop/`, Rust + iced). La ventana no tiene pantallas propias: lanza
`dotrino-vaultd --gui-bridge` y dibuja el modelo que le manda `src/tui/gui.js`, que corre
la misma sesión que la TUI (`handleKey`, `viewModel`). Una acción que se añade a la TUI
aparece en la ventana sin tocarla, y no hay manera de que una tenga algo que la otra no.

## Lo que atiende cada una

| Capacidad | Binario | Pestaña | Extensión |
|---|---|---|---|
| Emparejar, firmar, almacén, renovar, `check` | sí | sí | sí |
| Cajones de servicios (`vault.secrets`: claves, `enckey`, `digest`, guardar variables, `rewrap`) | sí | sí | sí |
| Consola remota (`vault.admin`), renuncia, avisos entre bóvedas | sí | sí | sí |
| Aprobaciones, concesiones, incidentes y aparatos bloqueados | sí | sí | sí |
| Ver y cortar concesiones **desde la administración** (`vault.admin` `grants` / `grant-revoke`, vault ≥ 0.119.0) | sí (TUI) | sí (`/vault` de la consola, con `admin`; antes solo en `/approvals` con `approve`, que la bóveda del navegador no se da) | el núcleo lo atiende; falta la pantalla (ver abajo) |
| Ver el valor de una privada desde la consola (`var.reveal`, con aprobación y sellado) | sí | sí | el núcleo lo atiende; falta la pantalla |
| Las bóvedas de la cuenta son clones: se pasan el acta, los cajones, la clave de contenido y el respaldo de las apps (`replicas.md` §11) | sí | sí | sí |
| La puerta: solo se atiende al acta (`core/gate.js`); los que salieron se borran solos | sí | sí | sí |
| Emparejar: reto y errores firmados; dos respuestas a una invitación = incidente | sí | sí | sí |
| Anunciar la invitación cerca (Bluetooth y red local) | sí (Linux: los dos; macOS/Windows: red local) | no: el navegador no puede anunciar | no |
| Timbre con asunto sellado; aviso `delivered` cuando un desatendido se lleva claves | sí | sí | sí |
| Cada servicio dice qué permisos del acta necesita | sí | sí | sí |
| Dispositivo o servicio se cambia sin re-enrolar (`cn`) | sí (`caps <ID> ±secrets:<ns>`, TUI) | el núcleo y `setCapsMany` lo aceptan; falta el control en la consola | igual |
| Pedir y avisar actualizaciones de los aparatos (`update-ask`, `update-done`) | sí | sí | sí |
| Dónde corre cada aparato (`machines`) | sí | sí | sí |
| Llave de comunicación (atender con el perfil cerrado) | sí | sí | sí |
| Llave de sellado de los sobres | sí | sí | sí (la guarda la pestaña; el worker se la pide al sellar el acta) |
| Entrar con usuario y contraseña | sí | sí | sí |
| Política de contraseñas (sin aprobador no se pide; con aprobadores, pedido al teléfono salvo `unattended`) | sí | sí | sí (antes preguntaba siempre en pantalla) |
| Anunciar la versión (`@dotrino/compat`) | `vaultd` | `vault` (versión de la librería) | `vault` |
| Bitácora encadenada | sí | sí (en IndexedDB) | sí |
| Réplicas (empujar a otra bóveda) | sí | sí (el núcleo lo hace; nadie configura una réplica desde el navegador todavía) | igual |
| Respaldo cifrado con contraseña: exportar todo o por cajón, importar con choques (`exportBackup`, `importBackup`, [`respaldo.md`](./respaldo.md)) | sí (`dotrino-vault backup`, la TUI con `o` y la ventana) | sí, en la consola (solo desde `vault.dotrino.com`) | sí, en la pestaña de bóveda; **sin las contraseñas del gestor**, que viven en el worker con su propia copia de recuperación |

## Lo que NO es igual, y por qué

Limitaciones de contexto, no olvidos:

- **Actualizarse sola.** La pestaña se sirve siempre al día y la extensión la actualiza su
  canal. No hay nada que instalar ni que aprobar.
- **El candado que cifra la maestra con la contraseña** y las **llaves de hardware** como
  puerta del perfil (`llaves-de-hardware.md`) son del binario: viven en `src/profiles.js`,
  fuera del núcleo. En el navegador la identidad tiene su propio candado, que impide usarla
  pero no cifra la maestra con la contraseña. Por eso el núcleo del navegador arranca con
  `hasPassword: false` y lo dice en el registro: la copia de recuperación de los cajones se
  cierra con la llave del almacén del navegador.
- **El mostrador local por socket** y la lectura de `/proc` no existen en el navegador: un
  servicio de la misma máquina llega por el proxio y lo que declara de su comando se enseña
  como declarado.
- **Atiende mientras la pestaña esté abierta.** La que está encendida siempre es la del
  binario.
- **En el navegador la maestra ES la llave del aparato** (dueño, 2026-10-25). La identidad
  de la pestaña firma con ella todo lo que firman las apps (`signData`, `identify`), y eso no
  es asunto de la bóveda: la regla de «la maestra tiene dos trabajos» es de la bóveda, no de
  la identidad. Lo que sí obliga a la bóveda del navegador es no firmar sola: el papel con el
  que su consola la administra (`selfCertIssuer`) se firma solo cuando cambian el acta o sus
  permisos, no cada minuto. En el binario la maestra y el aparato son llaves distintas.

## Inventario de lo nuevo del binario (lib 0.87.0 → 0.119.0, 2026-10-16 → 2026-11-04)

Casi todo entró por el **núcleo** (`lib/src/core/`), así que llegó a las tres en cuanto cada una
tomó la versión: la pestaña al re-vendorizar el iframe (`node dotrino-identity/vendor.mjs`) y la
extensión al construir (`extension/build.mjs` copia el núcleo del checkout de al lado; el
`package.json` de `dotrino-passmanager` solo lo usa `serve`).

| Versión del núcleo | Qué | Dónde vive | Llega a pestaña y extensión |
|---|---|---|---|
| 0.88 | un solo permiso para contraseñas y passkeys; borrar o pisar una passkey pregunta; el sí dura una hora deslizante | núcleo | sí |
| 0.89–0.90 | respaldo cifrado con contraseña | núcleo + pantallas (TUI, ventana, consola, pestaña de bóveda de la extensión) | sí (la extensión, sin contraseñas del gestor) |
| 0.91–0.96, 0.103 | la bóveda en una Lambda (alojada, réplica, segunda bóveda) | `lambda/` | no aplica: es otra forma del binario |
| 0.92–0.93 | reto, errores y secretos firmados; códigos en inglés | núcleo | sí |
| 0.97 | la consola elige qué bóveda administra (`to`) | núcleo + identity | sí |
| 0.98–0.99 | la puerta solo atiende al acta; los que salieron se borran solos | núcleo | sí |
| 0.100–0.102 | emparejar cerca (Bluetooth, red local) | plataforma (`bluetooth`, `lan`) | no: contexto |
| 0.101, 0.103.2 | aparato de usuario y contraseña: sin sesión no se atiende; nace con llave de cifrado | núcleo | sí |
| 0.103.1 | la bóveda del navegador no firma sola cada minuto | `browser.js` | sí (es del navegador) |
| 0.104–0.111 | renuncia única, ancla de la bitácora, las dos bóvedas son maestra, se pasan acta, cajones, clave de contenido, cadena de selladoras | núcleo | sí |
| 0.106 | ver una privada desde la consola (`var.reveal`) | núcleo + consola | pestaña sí; extensión sin pantalla |
| 0.109 | cada servicio dice qué permisos necesita | núcleo | sí |
| 0.112 | cada bóveda enseña lo suyo, en grupos | núcleo + TUI/consola | sí |
| 0.113 | el respaldo de las apps se copia entre las bóvedas | núcleo | sí |
| 0.114 | dispositivo o servicio sin re-enrolar | núcleo + identity + CLI/TUI | protocolo sí; control en la consola, no |
| 0.115 | `@dotrino/vault/atrest` exportado | librería | no aplica |
| 0.116 | el acta nueva se deja en la caché del proxio | núcleo | sí |
| 0.117 | un servicio aprende la selladora de la cadena | cliente de servicio | no aplica |
| 0.118 | timbre con asunto sellado; aviso `delivered` | núcleo | sí |
| 0.119 | concesiones desde la administración | núcleo + consola | pestaña sí; extensión sin pantalla |

**Lo que vive en `src/` (fuera del núcleo) y es de contexto, no un olvido:** `profiles.js` y
`adminDoor.js` (la contraseña del perfil que sella la maestra, la contraseña vacía con la llave de
la máquina, la puerta del admin para abrir a distancia, las llaves de hardware), `replica.js` (el
replicador), `selfupdate.js`/`update*.js` (actualizarse), `platform.js` (socket local, `/proc`,
Bluetooth y red local), la TUI y la ventana. Revisado `daemon.js`: lo que hace el respaldo, los
cajones y las concesiones es cablear funciones del núcleo, no lógica propia.

## Lo que falta (pantallas, no protocolo)

El núcleo ya atiende todo lo de arriba. Lo que el binario hace desde su TUI y el navegador
todavía no enseña:

- **El historial de una variable privada y volver a una versión** (`secret history/revert`): la
  consola remota no lo tiene a propósito (solo `var.reveal`, desde 0.106.0), y la pestaña
  administra por ese protocolo. En la TUI es local.
- **Cambiar un aparato a servicio y al revés** (`cn`) desde la consola: `setCapsMany` ya lo
  acepta (identity ≥ 0.135.0); falta el control en la fila del aparato.
- **Las contraseñas de la extensión en el respaldo.** La extensión respalda sus cajones, pero no
  sus contraseñas: las guarda el worker (único escritor de su almacén), con su propia copia de
  recuperación que se abre con la contraseña de recuperación del usuario, y la bóveda de la
  pestaña no las ve. Hace falta: (1) que el núcleo acepte de su plataforma quién le da y le
  guarda las contraseñas (`exportBackup`/`planBackupImport`/`importBackup` hoy leen su propio
  almacén sellado); (2) que el worker las abra con su llave de aparato y las vuelva a sellar a sus
  destinatarios al importar, firmando como autor; (3) el canal entre la pestaña y el worker. No
  entró en la revisión del 2026-11-04: toca el núcleo, el worker y el canal, y saca contraseñas
  en claro de un contexto a otro de la extensión, así que necesita su propio diseño y su prueba.
- **La pantalla de administración de la extensión** (aparatos, cajones, bloqueados,
  concesiones, ver una privada): la extensión tiene su propia identidad, distinta de la de
  `id.dotrino.com`, así que `vault.dotrino.com` no la administra. El núcleo ya responde a la
  consola remota; falta la pantalla dentro de la extensión, que hoy enseña los inicios de sesión
  y el respaldo. Es una pantalla entera (la de `/vault` de la consola), y no entró el 2026-11-04.
- **`dotrino-passmanager serve`** (la cuarta, en Node) sigue con el mostrador viejo
  (`startDeviceVault`, que se conserva solo para ella).
