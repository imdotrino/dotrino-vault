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
3. Ponle **nombre a la pila** (es también el de la función: 64 caracteres como mucho) y la
   **contraseña del administrador** (12 o más), y créala. Pide `CAPABILITY_IAM`: crea dos
   roles. **Cada pila es una bóveda distinta**: se pueden crear varias en la misma cuenta,
   porque todo lo demás lo nombra AWS o sale del nombre de la pila.
4. En **Outputs** sale `Login`: `admin@AB12-CD34-EF56`. Entra con esa dirección y la
   contraseña desde **«Iniciar sesión»** en cualquier app de Dotrino o en la terminal.

Ese usuario es un aparato más de la cuenta, con firma, lee, guarda, admin y aprueba. Desde
dentro se le cambian los permisos, se añaden aparatos o se quita.

La plantilla trae ya la URL del código y su **hash**: la pila baja el zip de la release, lo
comprueba y solo entonces lo usa. La contraseña pasa por Secrets Manager hasta el primer
arranque; la bóveda la usa para el registro (OPAQUE: no la guarda) y reescribe el secreto.

Desde un checkout, sin release: `lambda/deploy.sh <pila>` (arma el zip, lo sube a un
bucket de trabajo y despliega la misma plantilla).

## Cómo funciona

| Pieza | Qué hace |
|---|---|
| `template.yaml` | La pila entera: bucket del perfil, llave de KMS, secreto del admin, el que baja el código, rol, función (15 min de tope), Function URL y el primer arranque. El bucket y la llave se quedan aunque se borre la pila: son la cuenta. |
| `handler.mjs` | `POST /wake?k=…` comprueba el secreto, se invoca a sí misma en asíncrono y contesta 202 al instante. `{kind:'session'}` es la sesión. El recurso personalizado de CloudFormation es el primer arranque. |
| `session.mjs` | Una sesión: cerrojo en S3, bajar el perfil, arrancar **la misma bóveda del binario**, subir lo que cambie cada 2 s, apagarse tras **60 s sin mensajes** (o al llegar al tope) y, al final, desconectarse → subir → quitar el cerrojo. |
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

- `test/lambda-session.e2e.test.mjs`, en local con un proxio de verdad: el primer arranque
  crea el admin; con la bóveda dormida, admin entra con su contraseña, el canal vacío la
  despierta y sale con su certificado y sus permisos; sin mensajes se apaga sola; volver a
  desplegar no cambia la contraseña; el cerrojo deja una sesión a la vez y vence solo.
- En AWS (2026-10-17, us-east-1), la versión anterior por HTTP: arranque en frío desde S3 con
  la misma bóveda, todo cifrado. ~2,5 s en frío.

## Lo que falta

1. **Concurrencia reservada en 1**: una cuenta nueva no puede (límite 10, AWS exige dejar 10
   libres). Hay que pedir el aumento de cuota; mientras, el cerrojo lo cubre.
2. **Lo que la bóveda hace por reloj** (barrer pedidos vencidos, avisos agrupados) solo corre
   mientras hay sesión.
3. **La maestra queda bajo la llave de KMS**, sin contraseña del perfil: quien controle la
   cuenta de AWS y su KMS puede abrirla.
4. **Dos proxios**: el timbre vive en el nodo donde se registró. Si el mensaje entra por el
   otro, la federación lo lleva al home, que es el que despierta.
5. Sin confirmar: el `If-Match` del borrado en S3 (`DeleteObject`), que usa el cerrojo.
