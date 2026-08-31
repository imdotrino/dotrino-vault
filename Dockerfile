# Dotrino Vault en un contenedor.
#
# Por qué funciona sin abrir un solo puerto: el vault **no escucha nada**. Se conecta él
# hacia afuera al proxy del ecosistema por WebSocket, y tus aparatos lo alcanzan por ahí.
# Así que no hay `EXPOSE`, no hay `-p` y no hay nada que abrir en tu router.
#
# Y el CLI habla con el daemon **por archivos** dentro del dir de datos (ver
# `src/vaultControl.js`), no por un socket: por eso `docker exec` basta para controlarlo.
#
#   docker build -t dotrino-vault .
#   docker volume create dotrino-vault
#   docker run -d --name dotrino-vault --restart unless-stopped \
#     -e AWS_REGION=us-east-1 -e DOTRINO_KMS_KEY_ID=alias/dotrino-vault \
#     -v dotrino-vault:/data dotrino-vault
#
# El volumen es TU CUENTA: si lo borras, se perdió (no hay copia en ningún lado).
#
# ---------------------------------------------------------------------------------------
# EL PRIMER APARATO: los dos caminos, y cuál te toca
# ---------------------------------------------------------------------------------------
#
# El problema de un contenedor no es la bóveda: es el primer aparato. Una bóveda tiene que
# ENSEÑAR una invitación y RECIBIR de vuelta un código tecleado, y aquí no hay pantalla ni
# teclado. De ahí salen dos caminos, y la diferencia entre ellos es dónde está el humano.
#
# ── 1) CUENTA NUEVA, nacida aquí. Hay que entrar al contenedor: no hay otra ─────────────
#
#   Esta bóveda es la única, así que es ella la que tiene que invitar. Alguien tiene que
#   alcanzarla (`docker exec`, `kubectl exec`, `aws ecs execute-command`) — no es un
#   defecto, es lo que significa «enseñar algo y recibir una respuesta».
#
#     docker exec dotrino-vault dotrino-vault pair --admin --quiet
#     → escupe UNA línea: la invitación. Ábrela (o pégala) en vault.dotrino.com/vault
#     → el navegador enseña un código:
#     docker exec dotrino-vault dotrino-vault approve 123456
#
#   `--admin` es lo que la convierte en una CONSOLA (admitir y quitar aparatos). El QR no
#   lleva el permiso: es una nota local de la bóveda y se aplica al aprobar aquí, así que
#   una invitación interceptada sigue sin servir de nada.
#   `--quiet` da la invitación y termina, en vez de pintar un QR y esperar dos minutos.
#
# ── 2) YA TIENES UNA BÓVEDA. El contenedor se une a esa cuenta ──────────────────────────
#
#   Este es el camino para desplegar, y la razón es que **todo lo interactivo pasa del
#   lado donde hay un humano**: tu PC invita, el contenedor acepta, y el código que hay que
#   teclear lo teclas en tu PC. Al contenedor no hay que entrar NUNCA.
#
#     dotrino-vault pair --save invite.dpair          (en TU PC)
#     docker run -d … -e DOTRINO_JOIN_FILE=/run/secrets/invite … dotrino-vault
#     docker logs -f dotrino-vault   → «type this code in the other vault: 123456»
#     dotrino-vault approve 123456                    (en TU PC)
#
#   La invitación también entra por `DOTRINO_JOIN` a secas, pero un archivo es lo correcto:
#   una variable de entorno la ve cualquiera con `docker inspect`. Se usa UNA vez y queda
#   anotada: reiniciar el contenedor no vuelve a pedir entrar.
#
#   Y te deja donde quieres estar: dos bóvedas en la misma cuenta. Dale `+sella` a la nueva
#   (`dotrino-vault caps <ID> +sella` en tu PC) y podrá admitir aparatos ella sola el día
#   que la primera se pierda. Ver `docs/replicas.md`.
#
# ⚠️ EN UN CONTENEDOR, EL KMS NO ES OPCIONAL. Y esto costó descubrirlo:
#
#   Por defecto la clave del cifrado en reposo se deriva del material de la máquina. En
#   una imagen Alpine **no existe `/etc/machine-id`**, así que se cae al `hostname`, que
#   en Docker es el ID DEL CONTENEDOR y cambia en cada `docker run`. Con los datos en un
#   volumen —o en un EBS— el ciclo NORMAL (actualizar la imagen, `docker rm` y volver a
#   levantar, mover el disco a otra instancia) dejaba la cuenta **ilegible para siempre**,
#   y el único síntoma era un «unable to authenticate data».
#
#   Desde 0.55 eso ya no pasa en silencio: la bóveda guarda una huella de quién escribió y
#   se NIEGA a arrancar explicando el motivo. Pero negarse no recupera nada, así que:
#   **levanta el contenedor con KMS desde el primer día** (`DOTRINO_KMS_KEY_ID`, o
#   `DOTRINO_KEK_CMD` para OpenBao o el KMS que uses). Ahí la clave no depende de la
#   máquina y el contenedor pasa a ser lo que debe ser: desechable.
FROM node:22-alpine

# Solo dependencias de producción. `ws` es JS puro y `@dotrino/*` también: no hay
# módulos nativos que compilar, así que la imagen sale pequeña y sin toolchain.
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev --ignore-scripts --no-audit --no-fund \
  && npm cache clean --force

COPY bin ./bin
COPY src ./src
# El QR va vendorizado (JS puro, sin red ni telemetria): sin esto el daemon no arranca.
COPY vendor ./vendor
# El nucleo COMPARTIDO del lado-boveda (enroll/protocol/sealed): el daemon lo importa
# de ../lib/src para no tener dos copias del protocolo. Ver CLAUDE.md.
COPY lib/src ./lib/src
# El cliente de KMS: SigV4 en Node puro, sin el CLI de AWS (que pesa ~100 MB y traería
# Python a una imagen de 40). Ver la cabecera del archivo.
COPY packaging/kms-aws.mjs ./packaging/kms-aws.mjs
RUN npm link

# El dir de datos va SIEMPRE en el volumen: la identidad no puede vivir en la capa
# de escritura del contenedor, que se va con él.
ENV DOTRINO_VAULT_DIR=/data
# De dónde sale la clave del disco. Se dejan VACÍAS a propósito: si se pusiera un valor
# por defecto, todas las instalaciones de esta imagen compartirían llave, que es peor que
# no tener ninguna. Las pone quien despliega.
#   · DOTRINO_KMS_KEY_ID  → AWS KMS (id, ARN o alias/…). Necesita AWS_REGION.
#   · DOTRINO_KEK_CMD     → cualquier otro: OpenBao, gcloud, un script tuyo.
#                           Contrato: base64 por la entrada, base64 por la salida.
ENV DOTRINO_KMS_KEY_ID=""
ENV DOTRINO_KEK_CMD=""
# Entrar ya unido a la cuenta de otra bóveda (camino 2, arriba). Vacías: sin invitación,
# el contenedor arranca con su propia cuenta nueva y espera a que alguien lo empareje.
#   · DOTRINO_JOIN_FILE  → archivo con la invitación (lo correcto: un secreto montado)
#   · DOTRINO_JOIN       → la invitación a secas (la ve `docker inspect`)
#   · DOTRINO_JOIN_NAME  → cómo se llama aquí esa cuenta
ENV DOTRINO_JOIN_FILE=""
ENV DOTRINO_JOIN="" 
# Para que el CLI diga «docker restart …» y no «systemctl», que aquí no existe.
ENV DOTRINO_IN_DOCKER=1
VOLUME ["/data"]

# Sin root: el daemon no necesita privilegios y su dir es 0700.
RUN mkdir -p /data && chown -R node:node /data
USER node

# Comprobación de vida real: que el daemon esté vivo según SU propio contrato de estado,
# no que el proceso exista.
HEALTHCHECK --interval=60s --timeout=10s --start-period=20s \
  CMD dotrino-vault status > /dev/null 2>&1 || exit 1

ENTRYPOINT ["dotrino-vaultd"]
