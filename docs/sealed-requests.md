# Peticiones selladas: lo que un aparato le pide a su bóveda no viaja en claro

> Regla `encrypted` de la auditoría (dueño, 2026-10-26): **nada viaja en claro por la red**, ni
> en peticiones firmadas sin sellar ni al lado de un sobre. Hasta vault 0.119.0 las peticiones a
> la bóveda iban **firmadas pero no selladas**: el proxio leía el `machine` del aparato, el cajón
> que pedía (`ns`), el método del almacén, el `op` de la consola y los ids de los pedidos que se
> aprobaban. Implementado en vault 0.120.0 / vaultd 0.192.0, identity 0.136.0, proxy-client
> 0.47.0, remote-agent 0.33.0 y dotrino-native 0.50.0.

## 1. El diseño

Sin cripto nueva: es el sellado del pilar (`sendSealed` de `@dotrino/proxy-client`, que es
`wrapForMember` de `@dotrino/identity/content`, ECDH P-256 efímero → AES-256-GCM).

**La petición.** El mensaje ENTERO `{ type, data, signature, cert }` se sella a la llave de
cifrado del transporte de cada bóveda de la cuenta. Las bóvedas son los miembros del acta con
`cn: 'vault'` (sus llaves de comunicación, `core/commKey.js`); cada una anuncia su llave de
cifrado firmada al identificarse, y el pilar la averigua en el proxio y comprueba la firma
contra la llave de comunicación. Va un sobre por bóveda, **enrutado a la cuenta** (`master`):
así llega a todas, como antes, y sigue despertando a la que duerme (la de la Nube). Cada bóveda
abre el suyo y descarta los demás.

**La respuesta.** Dentro de lo firmado va `data.rek`, una llave de cifrado de un solo uso que
genera el aparato para esa conexión. La bóveda sella todo lo que contesta a ESA petición a
`rek` (`sendSealedTo(token, …, { peerEncPub: rek, pilar: true })`), en fila para que no se
adelanten (el aviso firmado de expulsión va antes del «no»). Como `rek` solo viaja dentro del
sobre de la petición, solo la bóveda que la abrió puede sellar a ella: una respuesta sellada a
`rek` es una respuesta de la bóveda.

**En la bóveda** no cambia ningún mostrador. `onMessage` mira si la petición vino sellada
(`meta.sealed`, lo abre el pilar con la llave de transporte) y, si es así, cambia `from` por un
canal de `channels` —el mismo mecanismo del socket local— que sella a `rek`. El canal es por
conexión **y** llave: un tercero que escriba «desde» ese token con otra llave se lleva su propio
canal, no el del aparato. Viven 24 h (lo que puede tardar un pedido que espera al teléfono).

**A qué bóvedas.** El aparato usa el acta que ya aceptó (identity: la guardada; un servicio: la
que verificó en la última respuesta, `service-identity.json`; remote-agent: `link.acta`) y, antes
de sellar, mira si el proxio guarda una más nueva que **encadene** con ella (`latestActa`, la
regla `canAdopt` de siempre): un aparato con el acta atrasada sellaría a una llave de
comunicación que la bóveda ya cambió, y la petición se perdería en silencio. Las apps nativas no
guardan acta en la cuenta del aprobador: piden al proxio la última y aceptan solo la que verifica
como sellada por la cuenta (`VaultSeal.accountRecord`); una vieja pero auténtica solo nombra
bóvedas de la cuenta.

## 2. Qué queda en claro, y por qué

| En claro | Por qué |
|---|---|
| `to_publickey` (la cuenta) y `quiet` | es lo que el proxio necesita para enrutar y para decidir si despierta |
| el token de quien escribe | lo pone el proxio |
| que es un sobre (`{ v: 1, sealed }`) y su tamaño | inevitable |
| el **emparejamiento** (`vault.hello`, `vault.enroll`, `vault.acta.sealed`) | el aparato todavía no es de la cuenta: no tiene acta de la que sacar a quién sellar. Pendiente: llevar la llave de cifrado de la bóveda en la invitación |
| la **entrada con contraseña** (`vault.login.*`) | OPAQUE: no lleva la contraseña ni deja adivinarla; quien entra todavía no conoce la bóveda |
| el **acta** publicada (`vault.admin.event`, `acta-put`/`acta-get`) | es pública y firmada por diseño; ver §4 |
| `vault.error` de la puerta (`too-many-tries`, `request-unsealed`, `no-reply-key`) | se dice antes de saber a dónde sellar; no lleva nada del aparato |

## 3. Migración — caduca el 2026-12-15

Las bóvedas se actualizan solas, los clientes no todos a la vez. Hasta el **2026-12-15 (UTC)**:

- **la bóveda** atiende una petición de esos tipos que llega en claro (`SEALED_REQUEST_TYPES`
  de `lib/src/protocol.js`) y lo dice en el log, una vez por tipo y hora:
  `vault.devices arrived UNSEALED from an old client: served until 2026-12-15 (migration)`.
  Desde esa fecha la rechaza con `request-unsealed`. El replicador hace lo mismo.
- **el cliente** (identity, `@dotrino/vault/service`, remote-agent, nativo) manda en claro si no
  hay a quién sellar (`no-vault-key`, `no-encpub`) y acepta una respuesta en claro de una bóveda
  vieja, y lo dice. Desde esa fecha falla con `vault-unsealable` / ignora la respuesta.

Pruebas: `test/sealed-requests.test.mjs` (vault: el cable, el cliente viejo, la fecha),
`test/vault-seal.test.mjs` (identity), `VaultSealTests.swift` y `VaultSealTest.kt`. **Quitar
los dos repliegues en cuanto pase la fecha.**

No sube `VAULT_PROTOCOL`: durante la migración el cable es compatible en los dos sentidos (un
cliente nuevo habla con una bóveda vieja —su pilar abre el sobre y contesta en claro— y uno viejo
con una nueva). Lo que corta es la fecha, no el protocolo.

## 4. Pendiente

- **El acta viaja en claro** cuando se publica (aviso a los miembros, caché del proxio) y lleva
  el inventario de la cuenta: miembros, sus `cn` (que nombran los cajones) y su `machine`. Es
  pública y firmada por diseño, pero eso es lo que ve el proxio. Decisión del dueño.
- **El emparejamiento**, como dice §2.
- **Las demás copias nativas** (`dotrino-terminal`, `dotrino-messenger`, `dotrino-padel-contador`,
  `dotrino-passmanager`, `dotrino-recorder` tienen `dotrino-native` como submódulo): tienen que
  subir el submódulo antes del 2026-12-15.
