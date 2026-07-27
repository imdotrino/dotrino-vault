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
#     -v dotrino-vault:/data dotrino-vault
#   docker exec -it dotrino-vault dotrino-vault pair
#
# El volumen es TU CUENTA: si lo borras, se perdió (no hay copia en ningún lado).
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
RUN npm link

# El dir de datos va SIEMPRE en el volumen: la identidad no puede vivir en la capa
# de escritura del contenedor, que se va con él.
ENV DOTRINO_VAULT_DIR=/data
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
