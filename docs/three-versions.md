# Las tres versiones del vault: qué tiene cada una hoy

> **Estado: inventario del 2026-09-17**, hecho leyendo el código, sin cambiar nada. Regla del
> dueño del mismo día: el vault existe **siempre** en tres versiones —la **pestaña**, la
> **extensión** y el **binario**—, **compatibles y con las mismas funciones**, salvo lo que
> limita su contexto; **el binario es la fuente de verdad**.
>
> Este documento dice **cuánto falta** para eso. Se hizo antes de construir el aparato que se
> abre con usuario y contraseña (`dotrino-passmanager/docs/temporary-access.md`) y las
> contraseñas selladas (`dotrino-passmanager/docs/sealed-passwords.md`), que tienen que ir en
> las tres.

## Qué es cada una

| Versión | Dónde vive | Piezas |
|---|---|---|
| **binario** | el demonio `dotrino-vault` | `src/vault.js`, `src/profiles.js`, `src/ctl.js` (CLI), `src/tui/app.js` |
| **pestaña** | `vault.dotrino.com` con «este aparato es la bóveda» | el iframe de identidad corre `startDeviceVault` (`lib/src/index.js`, desde `dotrino-identity/vault/vault.js`); `web/src/Vault.vue` atiende contraseñas; `web/src/Console.vue` administra |
| **extensión** | dentro del gestor | `dotrino-passmanager/extension/src/background.js`, `identity-core.js`, `popup.js` |

## La tabla

| Capacidad | Binario | Pestaña | Extensión |
|---|---|---|---|
| **Admitir un aparato en el acta** | sí (`lib/src/enroll.js` → `admitMember`; pide perfil abierto y sellador) | sí (mismo `createEnrollDesk`; además pide ser la pestaña visible y activa) | **no** |
| **Candado, frase y recuperación** | sí: la maestra va sellada con la llave de la contraseña; recuperación `#recovery` | a medias: el candado **no cifra**, solo impide llamar; la llave maestra no depende de la contraseña; sin recuperación | **no** hay candado cableado |
| **Identidad en el proxio con el perfil cerrado** | sí: llave de comunicación aparte (`src/commKey.js`) | **no**: usa la llave del perfil, que el candado bloquea | solo como cliente de otra bóveda; nunca escucha |
| **Atender a otros aparatos** | sí: firma, almacén, cajones, contraseñas, aprobaciones, administración | a medias: emparejar, renovar, firmar y contraseñas; **`get` y `store` no hacen nada** (el adaptador del iframe no los da); sin cajones ni administración | **no**: solo mensajes de sus propias páginas |
| **Aprobaciones** | sí: lee `unattended` del acta y avisa a los aprobadores | a medias: modal local y push; **ignora `unattended`** | a medias: solo local, y nunca recuerda un sí |
| **Estado por aparato guardado** | sí, cifrado en reposo; aprobaciones y concesiones en memoria | a medias (localStorage / IndexedDB, sin bitácora) | a medias (sin estado por aparato) |
| **Canales del proxio** | solo `list` (`src/sealers.js`), nunca publica | no | no |
| **Pantalla de aparatos** | a medias: CLI y TUI con permisos, revocar y nombre; **sin lista de aprobaciones ni concesiones** | a medias: permisos solo si es la maestra, y **sin `sealer`, `unattended` ni `replica`** | **no** |
| **Anunciar la versión (`@dotrino/compat`)** | sí | no (solo enseña la del demonio) | no |
| **Límite de intentos** | sí, solo al abrir el perfil: 5 y después espera que se duplica, tope 5 min, se olvida a los 15 | solo al abrir la identidad, sin olvido y sin código de error | no |

## Lo que importa para el aparato con contraseña

1. **La extensión no es una bóveda para otros aparatos.** No escucha en el proxio, no admite
   aparatos ni tiene pantalla de aparatos. Para que el aparato con contraseña exista también
   ahí, hay que construirle eso entero.
2. **La pestaña no atiende con el perfil cerrado**, ni si no es la pestaña visible, porque no
   tiene llave de comunicación. Y su `get`/`store` no hace nada.
3. **Admitir un aparato pide la bóveda abierta en todas.** No hay operación remota para
   admitir, y si `admitMember` falla, el error se anota y el certificado sale igual
   (`lib/src/enroll.js:357-368`).
4. **No existe un límite de intentos por aparato** con la forma decidida (5, y después una
   espera que se duplica). Hay uno por perfil en el binario y otro distinto en la identidad.
5. **No existe una lista de inicios de sesión con «cerrar» en ninguna.** Lo más parecido son
   las concesiones de aprobación, que solo lista y cierra la consola web contra el demonio.
6. **Anunciarse en un canal es nuevo en las tres.** `publish` firma con la llave de transporte
   y `list` no devuelve los datos extra, así que comprobar el acta pide una ida y vuelta como
   la de `src/sealers.js`. Además la huella que usa hoy el binario es la de la maestra
   (`src/vault.js:290`), no la del `profileId`, y eso importa con varias bóvedas.
7. **Ninguna guarda llaves cifradas ni registros OPAQUE**, y las contraseñas usan una sola
   llave por bóveda. Las contraseñas selladas no existen en ninguna.
8. **La política de aprobación no es la misma**: solo el binario lee `unattended`.
9. **Ninguna pantalla deja elegir `unattended` al crear un aparato**, y la consola no lo tiene
   ni para cambiarlo.
10. **Pestaña y extensión no anuncian su versión.**

## Fallos encontrados de paso

- **`dotrino-vault approval` revienta**: `src/ctl.js:1867` llama a `cmdApproval`, que no existe
  (`ReferenceError`). La lista de aparatos que piden aprobación se sustituyó por el permiso
  `unattended` (`caps <ID> +desatendido`), pero el comando y `docs/passwords.md` siguen
  diciendo `approval <ID> on`.
- **Que `admitMember` falle no para el emparejamiento** (punto 3): el aparato recibe su
  certificado sin estar en el acta.
