# Mapa de flujos de datos — qué se guarda, dónde y cuánto

> Escrito el 2026-09-02, **midiendo**, no citando: cada retención de aquí se comprobó contra
> el código o contra la base de datos en producción. Vive junto al
> [modelo de amenazas](./modelo-de-amenazas.md) porque se leen juntos.
>
> Esto es el documento técnico. La **política de privacidad** de cara al usuario es otra
> cosa y va en el sitio web.

## 1. El principio, y por qué la arquitectura ayuda

Lo compartible viaja por **`#fragment`**, que el navegador **no manda al servidor**. Un
enlace con contenido dentro no deja rastro en ningún log nuestro porque nunca llega. Eso no
es una política que haya que cumplir: es dónde está el dato.

Sin cookies, sin rastreadores, sin JavaScript de terceros. La analítica es autohospedada.

## 2. Lo que toca cada pieza

### `dotrino-proxy` — `proxy.dotrino.com`, `proxy2.dotrino.com`

Lo que más ve, porque todo pasa por ahí.

| Dato | Dónde | Cuánto |
|---|---|---|
| **Dirección IP** | en memoria por conexión; en `usage-stats.json`; y en el **log** de cada conexión | **30 días** sin volver a verse (`USAGE_STATS_RETENTION_DAYS`); el log, lo que rote pm2 |
| **Mensajes en cola** para quien está desconectado | SQLite, con el payload, el destinatario y quien lo mandó | **24 h**, y se purga al leer la cola |
| Pubkeys «en casa» | SQLite | 7 días |
| Suscripciones de Web Push | SQLite | hasta que el navegador las retire |
| Quién habla con quién, cuándo, cuánto | en memoria y en el log | mientras dure la conexión |

**Dos cosas que hay que decir en voz alta:**

- **La IP se guarda para frenar el abuso**, no para nada más: se cuentan mensajes y topes por
  IP para distinguir un ataque de un usuario. Hasta el 2026-09-02 **no se borraba nunca** —
  ahora caduca a los 30 días. Salió al escribir este documento.
- **El payload de la cola offline está en el disco del proxio hasta 24 h.** Si la app que lo
  mandó no lo selló, ahí es legible. El transporte **no cifra por sí solo**: ver
  [modelo de amenazas §4.1](./modelo-de-amenazas.md).

### GoatCounter — `goat.dotrino.com` (autohospedado, en nuestro VPS)

Comprobado contra la base de datos de producción el 2026-09-02: **no hay ni una columna de
IP en ninguna tabla.**

| Dato | Qué es |
|---|---|
| `session` | un **hash** de 16 bytes con salt rotatorio, no una IP y no reversible en la práctica |
| `location` | **el país** (`US`, `EC`…). Región solo para US/RU/CN |
| navegador, sistema, tamaño de pantalla, idioma | agregados |
| ruta visitada y referente | con el dominio por delante (la instancia es compartida) |

Sin cookies. Solo en producción — no cuenta en `localhost` ni en la LAN.

> ⚠️ **Retención: ninguna.** `data_retention` está en `0`, así que las visitas se guardan
> indefinidamente. Es lo mismo que le pasaba al throttling y **está sin decidir**: hay que
> fijar un número.

### `dotrino-content` — `content.dotrino.com`, bytes en R2 (`c.dotrino.com`)

Los bytes van **direccionados por hash y cifrados de punta a punta**; la llave viaja en el
`#fragment`. El node es del propio dueño. Lo único legible sin llave son las **copias
públicas** que alguien publica a propósito (los permalinks `dotrino.com/p/<cid>`), y eso es
su decisión, no un efecto colateral.

### El vault del VPS

Es la bóveda del dueño, no de los usuarios. Los secretos van sellados por destinatario; la
bitácora va cifrada y encadenada. Ver [`secretos-sellados.md`](./secretos-sellados.md) §9.

### El resto

| Pieza | Qué toca | Cuánto |
|---|---|---|
| `dotrino-geo` | pins georreferenciados **firmados**, con TTL propio | el TTL del pin |
| `dotrino-reputation` | atestaciones firmadas — **públicas por diseño**, para eso existen | permanente, es un registro |
| `dotrino-shortener` | el destino de un enlace corto | **1 mes**. Solo server-side, nunca con `#fragment` |
| `dotrino-signer` | **hashes**, nunca el contenido | permanente (es la prueba de cuándo) |
| `dotrino-feedback` | el formulario de contacto del sitio | se reenvía por correo y no se guarda |

## 3. Terceros que tocan algo

Se nombran porque un mapa de flujos que los esconde no sirve:

| Quién | Qué ve | Por qué |
|---|---|---|
| **Cloudflare** | tráfico del borde, DNS, y los bytes cifrados en R2 | CDN, Workers y almacenamiento |
| **GitHub Pages** | las peticiones a los sitios estáticos | ahí se sirven las apps |
| **Resend** | el contenido del formulario de contacto y el correo de quien escribe | es el que manda ese correo |
| **El proveedor del VPS** | el disco entero de las máquinas | ahí corren proxio, geo, vault y el node |
| **Ko-fi, Buffer, X, LinkedIn, Discord** | lo que se publica ahí a propósito | donaciones y difusión; nada del usuario |

Lo que **ninguno** ve: el contenido que viaja por `#fragment`, y lo que va sellado.

## 4. Lo que NO hay

- **Cuentas en nuestros servidores.** La identidad es una llave en tu aparato; no hay una
  tabla de usuarios que filtrar.
- **Cookies, ni de sesión ni de nada.**
- **Rastreadores ni JS de terceros**: nada de Google Analytics, Ads, Meta Pixel, Hotjar.
- **Venta ni cesión de datos**, ni publicidad. El proyecto no vive de eso
  (`MODELO-NEGOCIO.md`).
- **Perfilado.** No se cruza lo que hace una persona entre apps: no hay con qué, porque no
  hay identificador común que llegue al servidor.

## 5. Lo que queda por decidir

1. **La retención de GoatCounter.** Hoy es infinita. Hay que poner un número.
2. **La IP en el log del proxio.** Caduca por rotación de pm2, no por una política. Lo
   honesto es decidir si se sigue registrando o basta con el contador.
3. **Terminar el sellado del transporte** para que lo de la cola offline deje de importar
   (`PENDIENTES.md`).
