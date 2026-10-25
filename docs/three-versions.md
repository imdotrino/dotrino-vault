# Las tres versiones del vault: un solo núcleo

> **Estado: 2026-10-16.** Regla del dueño (2026-09-17): el vault existe **siempre** en tres
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

## Lo que falta (pantallas, no protocolo)

El núcleo ya atiende todo lo de arriba. Lo que el binario hace desde su TUI y el navegador
todavía no enseña:

- **Ver el valor de una variable privada, su historial y volver a una versión** (`secret
  show/history/revert`): la consola remota no lo tiene a propósito, y la pestaña administra por
  ese protocolo. En la TUI es local.
- **Listar y cortar concesiones** (`grants`) desde la pantalla.
- **Las contraseñas de la extensión en el respaldo.** La extensión respalda sus cajones, pero no
  sus contraseñas: las guarda el worker, con su propia copia de recuperación, y la bóveda de la
  pestaña no las ve. Hace falta que el worker exporte e importe las suyas con la misma pieza
  (`exportPasswordEntries` / `importPasswordEntries`).
- **La pantalla de administración de la extensión** (aparatos, cajones, bloqueados): la
  extensión tiene su propia identidad, distinta de la de `id.dotrino.com`, así que
  `vault.dotrino.com` no la administra. El núcleo ya responde a la consola remota; falta la
  pantalla dentro de la extensión.
- **`dotrino-passmanager serve`** (la cuarta, en Node) sigue con el mostrador viejo
  (`startDeviceVault`, que se conserva solo para ella).
