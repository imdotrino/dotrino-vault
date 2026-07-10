# @dotrino/vault

Usa **este dispositivo (navegador) como bóveda/CA** del ecosistema Dotrino, sin un PC
con el daemon. Es la contraparte browser del daemon `dotrino-vault`: atiende el mismo
protocolo de enrolamiento endurecido por el proxy y firma certificados de delegación
`D ← P` (donde `P` es la identidad de este dispositivo, `@dotrino/identity`).

Pensado para que **cualquier app** del ecosistema (no solo la terminal) pueda ofrecer
"usar este dispositivo como bóveda".

## Uso

```js
import { Identity } from '@dotrino/identity'
import { startDeviceVault } from '@dotrino/vault'

const identity = await Identity.connect()
const vault = await startDeviceVault(identity)          // se conecta al proxy como P

// 1) Abrir un emparejamiento y mostrar el QR/JSON al dispositivo a enrolar:
const { qr } = vault.startPairing({ label: 'mi-agente' })
// El dispositivo (p. ej. @dotrino/identity#enrollDevice) consume `qr`, GENERA un
// código aleatorio y lo MUESTRA (no lo envía).

// 2) Cuando el dispositivo pide acceso, aparece en la lista de pendientes:
vault.onPendingChange(() => {
  for (const { deviceId } of vault.listPending()) {
    // Un humano LEE el código del dispositivo y lo TIPEA aquí:
    // await vault.approve(deviceId, codigoTipeado)
  }
})

// 3) Máquinas ya enroladas / revocar:
const machines = await vault.listMachines()   // [{ sub, deviceId, label, exp, nonce, scope }]
// await vault.revoke(nonce)

vault.close()
```

## Modelo de aprobación (seguro por diseño)

- El **dispositivo** que se enrola genera un **código aleatorio** (`makePairingCode`) y
  lo **muestra**; el código **no viaja** por la red.
- Esta bóveda **no conoce** el código: un humano lo **lee del dispositivo** y lo **tipea**
  aquí. Al aprobar, la bóveda firma el cert y **echa** el código tipeado de vuelta.
- El dispositivo acepta el cert **solo si el código echado coincide** con el que generó.
  Así, una bóveda falsa (que nunca vio el código) no puede enrolarlo, y **aprobar a ciegas**
  (sin ir a leer el código del dispositivo) no enrola a nadie.

## API

`startDeviceVault(identity, { proxyUrl? }) → Promise<handle>`

- `startPairing({ scope?, ttlMs?, label? }) → { qr, expiresInMs }`
- `listPending() → [{ deviceId, label }]`
- `approve(deviceId, code) → Promise<{ ok, deviceId }>`  (code = lo que muestra el dispositivo)
- `reject(deviceId)`
- `listMachines() → Promise<[{ sub, deviceId, label, scope, exp, nonce }]>`
- `revoke(nonce) → Promise`
- `getSelfCert() → Promise<cert>`  (self-cert `P ← P`, para actuar además de cliente)
- `onPendingChange(fn)`, `close()`

Cripto y firma: `@dotrino/identity`. Transporte: `@dotrino/proxy-client`. No reimplementa
nada del ecosistema.

MIT · parte de [Dotrino](https://dotrino.com).
