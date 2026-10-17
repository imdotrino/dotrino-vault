# La bóveda en una AWS Lambda (prueba de concepto)

Una bóveda que **atiende peticiones** en vez de quedarse conectada al proxio. El objetivo
es correrla en una Lambda: sin máquina encendida, y pagando solo por uso.

```
servicio ──POST──▶ Function URL / API Gateway ──▶ Lambda (sin VPC)
                                                   ├─ núcleo de la bóveda (src/vault.js)
                                                   ├─ perfil: S3, reflejado en /tmp
                                                   └─ llave del disco: KMS
```

## Cómo está hecho

| Pieza | Qué hace |
|---|---|
| `lib/src/httpdesk.js` | El cliente. Con `DOTRINO_VAULT_URL` puesto, `@dotrino/vault/service` habla con la bóveda por HTTP, sin pasar por el proxio y **sin repliegue**: si el mostrador falla, se dice. |
| `lambda/desk.mjs` | El mostrador. Baja el perfil del almacén, arranca **la misma bóveda del binario** sobre ese directorio y pasa cada mensaje por `vault.localChannel`: el mismo enrutador y las mismas comprobaciones (cert + acta) que por el proxio. Después de cada petición sube lo que cambió. |
| `lambda/mirror.mjs` | El reflejo directorio ⇄ S3, con escrituras condicionales por `ETag`: dos escritores no se pisan, el segundo choca (`store-conflict`). |
| `lambda/handler.mjs` | El handler de la Lambda. |

Lo que llega a S3 va **cifrado**: la bóveda cifra en reposo cada archivo con una llave que
envuelve KMS (`packaging/kms-aws.mjs`, sin SDK). Un perfil nuevo **no nace** sin servicio de
llaves: en una Lambda la «máquina» cambia con cada contenedor, y una llave derivada de ella
dejaría la cuenta ilegible en el siguiente arranque en frío.

## Probado

`test/lambda-desk.e2e.test.mjs`, en local, con un proxio de verdad y un KMS de mentira:

- un servicio enrolado lee sus secretos por HTTP;
- se tira el directorio local, se arranca en frío desde el almacén, y el servicio sigue
  leyendo;
- ningún objeto del almacén lleva el secreto en claro;
- dos escritores sobre el mismo perfil: el segundo choca y lo del primero se conserva.

**No probado en AWS todavía.** Tampoco el `If-Match` del borrado en S3 (`DeleteObject`): la
subida condicional sí es de S3 desde 2024; la del borrado hay que confirmarla.

## Lo que falta (en este orden)

1. **Lo que se contesta después.** Por HTTP solo vuelve la primera respuesta. Una
   aprobación (el sí del teléfono), un aviso de cambio o el resultado de enrolar llegan
   más tarde y no tienen por dónde volver. Enrolar hoy va por el proxio.
2. **Despertar la Lambda desde el proxio.** Los aparatos hablan por pubkey; para que
   lleguen aquí, el proxio tiene que entregar por HTTP lo que va a esta bóveda (cambio en
   `websocket-proxy` y `@dotrino/proxy-client`).
3. **El arranque en frío se conecta al proxio** (`startVault` hace `identify`). Sirve para
   avisar al teléfono, pero cuesta tiempo en cada frío, y entre peticiones la conexión
   muere congelada.
4. **Lo que el núcleo hace por reloj** (barrer pedidos vencidos, agrupar avisos) no corre
   con la función congelada. Un cron de EventBridge, o hacerlo al entrar cada petición.
5. **Lo que se escribe después de contestar** se sube con la siguiente petición; si el
   contenedor muere antes, se pierde.
6. **La maestra queda bajo la llave de KMS**, sin contraseña del perfil: quien controle la
   cuenta de AWS y su KMS puede abrirla. Falta pasar la contraseña por petición para las
   dos cosas que la necesitan (firmar el acta, regenerar sobres).

## Desplegar (cuando toque)

- Runtime Node 22. El SDK de S3 (`@aws-sdk/client-s3`) ya viene en el runtime.
- Zip con `bin/ src/ lib/src/ vendor/ packaging/kms-aws.mjs lambda/ node_modules/`
  (producción) y handler `lambda/handler.handler`.
- Variables: `DOTRINO_VAULT_BUCKET`, `DOTRINO_VAULT_PREFIX` (opcional), `DOTRINO_KMS_KEY_ID`,
  `DOTRINO_PROXY_URL` (opcional).
- Rol: `s3:GetObject`/`PutObject`/`DeleteObject`/`ListBucket` sobre el prefijo, y
  `kms:Encrypt`/`kms:Decrypt` sobre esa llave. Nada más.
- **Concurrencia reservada: 1.** Dos contenedores a la vez se pisarían el perfil; la
  escritura condicional lo para, pero mejor que no pase.
- Function URL con `AuthType: NONE`: la puerta es el cert de cada mensaje, como en el
  proxio. Alcanzar la URL no autoriza nada.
