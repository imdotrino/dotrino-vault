# Cuestionario de seguridad, respondido por adelantado

> Escrito el 2026-09-02. Sigue la estructura de dominios del **CAIQ v4** (Cloud Security
> Alliance) porque es lo que un comprador corporativo manda por correo. **No es un CAIQ
> oficial rellenado**: es el mismo terreno, respondido antes de que nadie pregunte y con
> enlaces a la evidencia.
>
> Se lee con el [modelo de amenazas](./modelo-de-amenazas.md) y el
> [mapa de flujos de datos](./flujos-de-datos.md).

## Lo primero, porque cambia todas las respuestas

**Dotrino es software que te instalas, no un servicio que operamos por ti.** Eso mueve la
mayoría de los controles a tu lado de la línea, y hay que decirlo antes de responder nada:

| | Quién responde |
|---|---|
| El vault, tus llaves, tus datos | **tú**, en tu máquina |
| Los paquetes y los instaladores que distribuimos | nosotros |
| `proxy`, `geo`, `reputation`, `results`, el node oficial | nosotros, y **solo** eso |

Consecuencia incómoda y honesta: **una certificación tipo SOC 2 auditaría solo la tercera
fila**, que es la parte pequeña. Lo que de verdad decide tu riesgo es la primera, y ahí el
control es tuyo por diseño.

**Y el tamaño, porque cambia lo que es creíble:** un mantenedor. No hay equipo de seguridad,
ni turnos, ni SLA. Donde eso importa, se dice.

---

## A&A · Auditoría y aseguramiento

**¿Tienen SOC 2, ISO 27001, u otra certificación?** No. Ninguna, y hoy no se busca: ver
`CUMPLIMIENTO.md` §5 para el porqué y el orden.

**¿Auditorías externas?** Todavía no. **Nadie de fuera ha revisado la criptografía ni ha
hecho un pentest.** Es la siguiente inversión de la lista y está sin hacer.

**¿Entonces qué pueden enseñar?** Invariantes afirmados por pruebas, que se pueden leer y
ejecutar: la maestra no firma con el perfil cerrado, la llave de comunicación no recibe
sobres, nada queda en claro en el disco, tocar el pasado de la bitácora rompe la cadena.
La lista con su test está en el [modelo de amenazas §3](./modelo-de-amenazas.md).

## AIS · Seguridad de aplicaciones e interfaces

Sin JavaScript de terceros en ninguna app. Sin cookies. Lo compartible viaja por
`#fragment`, que no llega al servidor. Frescura anti-replay de ±5 min y nonce de un solo uso
en las operaciones administrativas.

Revisión de código: **un solo mantenedor**, así que no hay revisión por pares real. `main`
va protegida (PR obligatorio con una aprobación, sin force-push ni borrado), pero el dueño
la salta por ser admin — eso es lo que hay con una persona, y fingir lo contrario sería peor.

## BCR · Continuidad y recuperación

**No hay SLA ni compromiso de disponibilidad.** Es software libre mantenido por una persona.

Por diseño, la disponibilidad no depende de nosotros: **ninguna app puede exigir que haya un
daemon, un VPS o un node encendido**. El almacén vive en tu aparato y responde sin conexión.
Lo dedicado añade alcance, no permiso.

**Recuperación ante desastre, dicho claro:** la recuperación devuelve **la identidad, no los
datos**. Si pierdes tu disco, lo que estaba solo ahí se fue. Y lo que sobreviva cifrado en
otro sitio (respaldo, node) **no se vuelve a abrir**, porque las llaves que descifran no
están en ningún material de recuperación. Es una decisión tomada a propósito, anotada en
`PENDIENTES.md`.

## CCC · Control de cambios

Todo en GitHub, público, con historia. `main` protegida. Los despliegues salen de CI.

Desde el 2026-09-02 **las versiones del vault se construyen y publican desde CI**, no desde
un portátil: cada `.deb`, tarball y SBOM lleva una **atestación de sigstore** que lo ata a su
commit y a su workflow. Se comprueba con
`gh attestation verify <archivo> --repo imdotrino/dotrino-vault`.

## CEK · Criptografía y gestión de llaves

Donde el producto es fuerte, y por eso va con detalle.

- **ECDSA P-256** para firmar, **ECDH P-256** para sellar, **AES-256-GCM** para el contenido.
  Nada propio: `crypto.subtle` y `node:crypto`.
- **La llave maestra tiene dos trabajos y ninguno más**: sellar el acta y regenerar sobres al
  abrir. Va **sellada con tu contraseña**; con el perfil cerrado **no está en memoria** y no
  firma. Tampoco se regenera: una identidad que se inventa un par nuevo deja al dueño fuera
  para siempre y en silencio.
- **Los secretos van sellados por destinatario**, no cifrados «para el servidor»: cada uno
  lleva su envoltura y el que lo escribió va **firmado**. Un `cn` no puede sobrescribir un
  sobre ajeno ni poner uno fuera de su cajón.
- **Cifrado en reposo** de todo el disco del vault, con clave derivada de la máquina — y con
  proveedor **KMS** disponible (`atrest rekey`) para que deje de estar en ese disco.
- **En el navegador la privada es no extraíble**: ni el propio código lee sus bytes.

**Lo que no está cerrado:** tres llaves ceden a la llave de la máquina (dos a propósito, para
poder servir con el candado echado). Ver [modelo de amenazas §4.2](./modelo-de-amenazas.md).

## DCS · Centros de datos

No operamos ninguno. Se apoya en un VPS alquilado, Cloudflare y GitHub Pages — nombrados en
el [mapa de flujos §3](./flujos-de-datos.md). **La seguridad física es de ellos**, y quien se
lleve el disco de un VPS se lleva con qué descifrarlo mientras la clave viva ahí (§2.2 del
modelo de amenazas). Ese es el argumento para el KMS.

## DSP · Datos y privacidad

Ver el [mapa de flujos](./flujos-de-datos.md) entero. En corto:

- **No hay cuentas en nuestros servidores.** La identidad es una llave en tu aparato: no hay
  una tabla de usuarios que filtrar.
- **No se venden ni se ceden datos**, y no hay publicidad ni perfilado.
- Analítica **autohospedada y sin IPs** (comprobado contra la base de datos: no hay una sola
  columna de IP).
- El proxio guarda **IPs para frenar abuso**, 30 días. Y los mensajes en cola para quien está
  desconectado, **24 h**.
- **Pendiente y dicho:** la retención de la analítica es hoy infinita.

## GRC · Gobierno y cumplimiento

Una persona. Sin comité, sin política corporativa. Lo que existe está escrito y es público:
`CLAUDE.md` (las reglas duras), `CUMPLIMIENTO.md` (el camino), y estos tres documentos.

**El CRA de la UE sí nos alcanza**, porque distribuimos software. SBOM, releases firmados y
gestión de vulnerabilidades ya están; el resto está en `CUMPLIMIENTO.md` §4.

## HRS · Personal

**Un mantenedor**, y un colaborador con acceso de escritura a los repos públicos. No hay
verificación de antecedentes, ni formación en seguridad, ni segregación de funciones — con
una persona no puede haberla. Los repos privados **no tienen colaboradores**, a propósito.

## IAM · Identidades y accesos

El corazón del producto. **El acta manda**: qué puede cada aparato lo dice ella, va firmada
por la maestra, y quitar un aparato es quitarle la llave. No hay una segunda lista.

- Permisos por capacidad (`sign`, `secrets`, `admin`, `approve`, `sealer`, `unattended`…),
  no por tipo de aparato.
- Un papel bien firmado de un aparato que el acta ya no nombra **no entra**.
- **Recibir claves privadas sin aprobación es un permiso** (`unattended`) que se concede a
  propósito; sin él, cada entrega pide aprobación en otro aparato.
- Un servicio ve **su** cajón y sus revocaciones, **no el inventario de aparatos del dueño**.

**Lo que no hay:** SSO, SAML, SCIM, directorio corporativo. Hay diseño escrito para OIDC
(`dotrino-sso`) y para AD, sin implementar.

## IPY · Portabilidad

Todo es MIT y autohospedable. Los datos son tuyos y están en tu máquina; los bytes van
direccionados por hash. No hay bloqueo: **el caso normal es que te lo lleves.**

## IVS · Infraestructura

Servicios en un VPS con `pm2`, detrás de nginx y Cloudflare. Sin contenedores en producción.
El vault corre como servicio **de usuario** (`systemd --user`), con sus datos en el `$HOME`.

## LOG · Registro y monitorización

**Bitácora de seguridad encadenada por hash** desde vaultd 0.94: quién firmó, renovó, enroló
o fue rechazado. Reescribir o quitar una entrada rompe la cadena y `activity --verify` dice
dónde. Rota **archivando**, con retención declarada (5 archivos), y cuando uno se cae del
borde **queda anotado**. Exportable con `activity --export`.

**Limitación afirmada en un test:** cortar el **final** deja un prefijo válido. Cerrarlo pide
anclar el último hash fuera de la máquina.

**No hay** SIEM, ni alertas, ni monitorización 24/7.

## SEF · Incidentes

Política de divulgación coordinada en
[`SECURITY.md`](https://github.com/imdotrino/.github/blob/main/SECURITY.md), heredada por los
67 repos públicos, con **reporte privado de vulnerabilidades** activado y
`security@dotrino.com`. `security.txt` (RFC 9116) en los dominios.

Los plazos son los que **una persona puede cumplir**, y están escritos ahí en vez de
prometerse. No hay guardia ni retribución por hallazgos: se da crédito.

## STA · Cadena de suministro y terceros

- **`.npmrc` obligatorio en las apps**: `ignore-scripts=true` (el vector número uno de
  inyección en npm) y `save-exact=true`, así que cada subida de dependencia es un cambio
  explícito y auditable en el diff.
- **SBOM CycloneDX por release**, adjunto a la release.
- **Publicación con confianza OIDC**: sin ningún token guardado, y npm firma la procedencia.
- **Artefactos atestiguados** por sigstore.
- Terceros nombrados en el [mapa de flujos §3](./flujos-de-datos.md).

**Lo que falta:** de 20 paquetes, **solo el vault publica así hoy**; los otros 19 son deuda
que vigila el índice. Y **no hay Dependabot ni análisis estático (CodeQL)** configurados.

## TVM · Vulnerabilidades

Canal de reporte: arriba. `npm audit` a mano, no en CI. **Sin pentest, sin escaneo
automático, sin CVEs publicados todavía.** Cuando toque, por GitHub Security Advisories, que
es el mecanismo que el CRA da por supuesto.

## UEM · Dispositivos

No gestionamos los tuyos y no queremos. Lo que sí: **cada aparato tiene su llave**, el acta
dice qué puede, y **revocar corta el acceso de verdad** — hay un test que lo comprueba de
punta a punta.

---

## Resumen honesto para quien decide

**A favor:** la arquitectura quita categorías enteras de riesgo en vez de gestionarlas — no
hay cuentas que filtrar, no hay datos tuyos en nuestros servidores, las llaves están en tu
aparato, todo es MIT y auditable, y la cadena de suministro está firmada de punta a punta.

**En contra, y sin adornos:** un mantenedor, sin certificaciones, **sin revisión externa ni
pentest**, sin SLA, sin SSO, sin monitorización. Y una lista concreta de lo que no se cubre,
que está escrita en el [modelo de amenazas §4](./modelo-de-amenazas.md) en vez de escondida.

Si tu decisión depende de un papel firmado por un auditor, hoy no lo tenemos. Si depende de
poder leer el código, ejecutar las pruebas y comprobar de qué commit salió el binario que
instalas, eso sí.
