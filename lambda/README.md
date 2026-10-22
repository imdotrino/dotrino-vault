# La bóveda en una AWS Lambda (prueba de concepto)

Una bóveda que **no vive conectada**: duerme hasta que alguien la necesita. El proxio la
despierta, ella trabaja por WebSocket como cualquier bóveda y se apaga sola cuando deja de
haber trabajo. Sin máquina encendida, y pagando solo los segundos que trabaja.

```
proxio ──POST /wake?k=…──▶ Function URL ──▶ Lambda ──(invocación asíncrona)──▶ sesión
   ▲                                                                            │
   └──────────── WebSocket: identify, lo encolado, todo lo demás ───────────────┘
                 perfil en S3 (reflejado en /tmp) · llave del disco en KMS
```

## Desplegar (cualquier cuenta de AWS)

1. Baja `dotrino-vault-lambda-<versión>.yaml` de la
   [release](https://github.com/imdotrino/dotrino-vault/releases/latest).
2. CloudFormation → **Crear pila** → sube ese archivo.
3. Pon el **nombre** de la bóveda (`Name`) y la **contraseña del administrador** (12 o más),
   y créala. Pide `CAPABILITY_IAM`: crea dos roles. **Cada nombre es una bóveda**: se pueden
   tener varias en la misma cuenta, y el mismo nombre da siempre los mismos recursos
   (`dotrino-vault-<nombre>-<cuenta>-<región>`, `dotrino-vault-<nombre>`,
   `alias/dotrino-vault-<nombre>`).
4. En **Outputs** sale `Login`: `admin@AB12-CD34-EF56`. Entra con esa dirección y la
   contraseña desde **«Iniciar sesión»** en cualquier app de Dotrino o en la terminal.

Ese usuario es un aparato más de la cuenta, con firma, lee, guarda, admin y aprueba. Desde
dentro se le cambian los permisos, se añaden aparatos o se quita.

La plantilla trae ya la URL del código y su **hash**: la pila baja el zip de la release, lo
comprueba y solo entonces lo usa. La contraseña es un parámetro oculto (NoEcho) que el primer
arranque usa para el registro (OPAQUE: la bóveda no la guarda); después no se vuelve a leer.
Cámbiala al entrar.

**Varias bóvedas, una llave** (`SharedKeyArn`): una llave de KMS cuesta $1/mes. Con el ARN de
una llave compartida la pila no crea la suya; el nombre de la bóveda va en el contexto de
cifrado y su rol solo puede usar la llave con ese nombre, así que una bóveda no abre el sobre
de otra. Es lo que usan las bóvedas alojadas de `dotrino-accounts`.

**Límite de permisos** (`PermissionsBoundary`): vacío en tu propia cuenta. Con el ARN de una
política de IAM, los dos roles de la pila la llevan como límite: no pueden hacer más de lo que
ella dice, tenga lo que tenga dentro su política. Así se le puede dar a quien crea la pila
permiso para crear roles **solo con ese límite**, que es como `dotrino-accounts` crea las bóvedas
alojadas sin poder fabricar un rol con más permisos.

Desde un checkout, sin release: `lambda/deploy.sh <nombre>` (arma el zip, lo sube a un
bucket de trabajo y despliega la misma plantilla).

## Modo réplica (`Mode: replica`)

Una **réplica** de una cuenta que ya tienes, en vez de una cuenta nueva: no tiene maestra, no
abre nada y entra al acta **sin llave de cifrado** (`../docs/replicas.md` §8.bis). Hace que la
cuenta conteste con tu bóveda apagada. Es lo que vende `dotrino-accounts` como réplica alojada.

1. Crea la pila con `Mode: replica`, sin `AdminPassword` y con **`Owner`**: la cuenta en la que
   puede entrar (`pubkeyId` de la llave del perfil, 64 hex). No nace nada: espera a su dueño.
2. En tu bóveda: `dotrino-vault pair --scope replica --quiet` (la invitación vale 5 minutos).
3. Invoca la función con `{ "kind": "enroll", "invitation": "<invitación>" }`: contesta
   `{ deviceId, code }`.
4. En tu bóveda: `dotrino-vault approve <código>`. La réplica recibe el acta y los sobres, y
   registra su **timbre**, que es de SU llave (`websocket-proxy` ≥ 1.8.0): lo que un servicio
   le escribe cuando la bóveda no contesta la despierta.

**Solo entra en la cuenta `Owner`.** La bóveda manda en el reto del alta su cadena de
selladoras, y la raíz la firma la llave del perfil. Si la cuenta es otra, la réplica no enseña
ningún código y contesta `wrong-account`: no hay nada que aprobar. Una bóveda anterior a vault
0.95.0 no manda la cadena, y la réplica tampoco entra (actualízala).

`{ "kind": "status" }` dice si está enrolada y por qué acta va. **Una réplica enrolada no se
vuelve a enrolar** (`already-enrolled`): no es multiperfil. Si el alta no llegó a aprobarse,
se repite con otra invitación.

## Volver a montar una pila borrada

El bucket y la llave **se quedan** al borrar la pila: son la cuenta. Crear otra con el mismo
`Name` chocaría con el bucket, así que se le dice que los use: el ARN de la llave va en
**`ExistingKeyArn`** (sale en los Outputs como `KeyArn`; apúntalo) y el bucket sale del
nombre. La bóveda vuelve con su perfil y sus usuarios; la contraseña del administrador no se
toca. Desde un checkout: `lambda/deploy.sh <nombre> --key <arn>`.

## Modo segunda bóveda (`Mode: join`)

Una **segunda bóveda** de una cuenta que ya tienes: tiene maestra propia y **sella** el acta
(`../docs/replicas.md` §1.bis), así que la cuenta puede admitir aparatos y cambiar permisos aunque
tu otra bóveda no exista. Es lo que vende `dotrino-accounts` por $5 (`dotrino-accounts/docs/
DISENO.md` §5).

**Su maestra va sellada con una contraseña tuya**, puesta al darla de alta (`lock.mjs`): KMS
cifra el disco, pero sin la contraseña no se abre. Cerrada sirve (se identifica, reparte sobres);
lo que necesita la maestra contesta `vault-locked`, y se abre desde tu consola con el «abrir a
distancia» de siempre (`../docs/abrir-a-distancia.md`): la consola deriva aquí la contraseña y
manda solo la derivada, sellada a una llave efímera. Abierta lo está **mientras dura la sesión**.

1. Crea la pila con `Mode: join`, sin `AdminPassword` y con **`Owner`**, como la réplica.
2. En tu bóveda: `dotrino-vault pair --scope sella,firma,lee,guarda --quiet`.
3. Invoca la función con `{ "kind": "enroll", "invitation": "<invitación>" }`: contesta
   `{ req, door: { ek, salt, N, r, p, len } }`. La maestra todavía no existe.
4. Deriva `scrypt(contraseña, salt, N, r, p, len)` y séllala a `ek` (`seal` de
   `@dotrino/vault/sealed`, con `{ nonce: req, key }`). Invoca `{ "kind": "enroll-door", req,
   enc }`: contesta `{ deviceId, code }`. Ahora nace la maestra, ya sellada.
5. En tu bóveda: `dotrino-vault approve <código>`.

**Se le habla por su llave de comunicación.** El acta dice de qué bóveda es cada una (`vault` en el
miembro con `cn: 'vault'`, `@dotrino/identity` ≥ 0.125.0), y la consola elige a cuál hablarle con
`vaultAdmin(op, { to })`. Por la maestra no llega: la del perfil la reciben todas las bóvedas de la
cuenta, y la de esta se entrega a los aparatos que ella emparejó. Por eso también se despierta por
esa llave (timbre `self`), además de por la cuenta.

Igual que la réplica: **solo entra en la cuenta `Owner`** (`wrong-account` antes del código), no
es multiperfil (`already-enrolled`), y un alta que falla no deja nada en el bucket. La contraseña
**no se recupera**: si se pierde, esa bóveda no vuelve a sellar y la quitas desde la otra.

## Cómo funciona

| Pieza | Qué hace |
|---|---|
| `template.yaml` | La pila entera: bucket del perfil, llave de KMS (o la compartida), el que baja el código, rol, función (15 min de tope), Function URL y el primer arranque. El bucket y la llave se quedan aunque se borre la pila: son la cuenta. |
| `handler.mjs` | `POST /wake?k=…` comprueba el secreto, se invoca a sí misma en asíncrono y contesta 202 al instante. `{kind:'session'}` es la sesión. El recurso personalizado de CloudFormation es el primer arranque. |
| `session.mjs` | Una sesión: cerrojo en S3, bajar el perfil, arrancar **la misma bóveda del binario** (o el mismo replicador), subir lo que cambie cada 2 s, apagarse tras **60 s sin mensajes** (o al llegar al tope) y, al final, desconectarse → subir → quitar el cerrojo. También el alta de una réplica (`enrollReplica`) o de una segunda bóveda (`enrollJoin`), y su estado. |
| `lock.mjs` | El candado de la segunda bóveda: `lock.json` (la llave del perfil envuelta con la derivada de la contraseña, cifrado además con KMS) y el freno de intentos, los mismos que la contraseña del admin de escritorio (`../src/adminDoor.js`). |
| `mirror.mjs` | El reflejo directorio ⇄ S3 con escrituras condicionales por `ETag`, y el cerrojo (`.lease`, vence solo si el contenedor muere). |
| `bootstrap.mjs` | El primer administrador (`createPasswordLogin`, el mismo camino que `dotrino-vault logins add`). |
| `build.sh` | El zip (reproducible) y la plantilla con la URL y el hash puestos. Lo corre `release.yml`. |

**El despertar** lo hace el proxio (`websocket-proxy` ≥ 1.7.0): la bóveda registra su URL al
identificarse (`registerWake`, `@dotrino/proxy-client` ≥ 0.38.0), firmada con su llave de
comunicación y con el acta. El registro es **permanente** y es de la cuenta. La despiertan:

- un mensaje para la cuenta sin nadie suyo conectado (se encola y se entrega al identificarse);
- listar el canal de la cuenta vacío: es lo que hace **«Iniciar sesión»**, que espera hasta
  30 s a que la bóveda se anuncie.

Lo que hay en S3 va **cifrado** (`DOTRINO-ATREST-v1`), salvo `atrest.json`, `atrest.kek` y
`key.json` (solo la llave pública del dueño del directorio), que van en claro a propósito. El
secreto de despertar (`.wake`) va cerrado por KMS.

## Probado

- `test/lambda-join.e2e.test.mjs`: la segunda bóveda pide la contraseña antes de nacer, entra
  con el código del dueño y sella; su maestra no se abre con el bucket y KMS en la mano; la
  sesión arranca cerrada y se abre con la derivada, no con otra; con la invitación de otra
  cuenta no hay código y no queda nada a medias.
- `test/lambda-session.e2e.test.mjs`, en local con un proxio de verdad: el primer arranque
  crea el admin; con la bóveda dormida, admin entra con su contraseña, el canal vacío la
  despierta y sale con su certificado y sus permisos; sin mensajes se apaga sola; volver a
  desplegar no cambia la contraseña; el cerrojo deja una sesión a la vez y vence solo.
- En AWS (2026-10-17, us-east-1), la versión anterior por HTTP: arranque en frío desde S3 con
  la misma bóveda, todo cifrado. ~2,5 s en frío.

## Lo que falta

1. **Sin concurrencia reservada, y no hace falta**: dos sesiones a la vez las impide el cerrojo
   (`.lease`). `ReservedConcurrency` es opcional: solo aparta un hueco para la bóveda en una
   cuenta cuyas otras Lambdas puedan ocupar todo su límite (una cuenta nueva no puede
   reservar: AWS exige dejar 10 libres).
2. **Lo que la bóveda hace por reloj** (barrer pedidos vencidos, avisos agrupados) solo corre
   mientras hay sesión.
3. **En modo `vault` la maestra queda bajo la llave de KMS**, sin contraseña del perfil: quien
   controle la cuenta de AWS y su KMS puede abrirla. En modo `join` va sellada con la contraseña
   del cliente; mientras está abierta (una sesión), está en la memoria de la Lambda.
4. **Dos proxios**: el timbre vive en el nodo donde se registró. Si el mensaje entra por el
   otro, la federación lo lleva al home, que es el que despierta.
5. Sin confirmar: el `If-Match` del borrado en S3 (`DeleteObject`), que usa el cerrojo.
