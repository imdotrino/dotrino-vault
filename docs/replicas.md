# Réplicas de la bóveda (diseño — no implementado)

> Anotado el 2026-08-30, a raíz de comparar la bóveda con un KMS. **Hoy la bóveda
> es una sola máquina: sin réplica, sin relevo y sin SLA.** Un KMS de nube es
> multi-zona. Esto es el plan para cerrar esa parte.

## 1. El problema, y por qué duele más de lo que parece

Si la máquina del vault está apagada, un servicio que necesita su secreto **no
falla: espera**. `waitForSecrets` reintenta para siempre, y `secretos-sellados.md`
ya lo dejó escrito como «el error que más caro salió» — porque desde fuera no se
distingue de que todo va bien.

Y hay un reloj peor: **los certificados de aparato duran 30 días** y solo la
maestra los renueva. Una bóveda apagada un mes no deja un servicio esperando; deja
el ecosistema entero caducado.

## 1.bis DECIDIDO (2026-08-30): son DOS BÓVEDAS, no una y su réplica

El dueño lo cerró así, y cambia lo que dice el resto de este documento:

1. **Las dos pueden sellar el acta.** `cosealers` en `@dotrino/identity` (hecho). El
   argumento: *«usualmente no se abren los dos al mismo tiempo»* y *«me resuelve el
   problema de un desastre que pierda permanentemente un vault»*.
2. **A la segunda se le envuelven los sobres que se puedan envolver**, también los de los
   cajones con dueño. Los reparte quien pueda: el propio servicio (ya tiene la CEK, no
   gana nada) y, lo que falte, **la bóveda A al abrirse** — que es el mecanismo de deuda
   que ya existía para cualquier miembro que entra tarde.
3. **La llave de transporte no recibe sobres. Nunca.** Firmar no es leer.

Lo que eso deja obsoleto de las secciones siguientes: **§2 ya no aplica tal cual** (sí hay
dos selladores) y **§5 tampoco** (no hace falta una CA intermedia para renovar certs: la
segunda bóveda sella actas, así que puede emitir).

Y el precio, que no se esconde: a partir de aquí son **dos los discos** cuya captura abre
un cajón, y el empate a igual `seq` deja de ser imposible para ser raro. Lo resuelve
`canAdopt` con las reglas que ya estaban —gana el traspaso, si no la de hash menor— y lo
que pierde el desempate **se pierde**, así que falta avisarlo (§2.4.1.5 del acta).

## 2. La restricción dura: UN SOLO SELLADOR

`acta-de-perfil.md` §2.4 es tajante y no se negocia: con un sellador (D4) y llaves
intransferibles (D1), **dos actas legítimas con el mismo `seq` son
criptográficamente imposibles**. No hay merge, no hay precedencia, no hay votación.

Por lo tanto: **las réplicas no sellan.** Ni una, ni bajo ninguna condición. Lo
que se replica es *servir*, no *decidir*. Es la misma línea que ya existe en la
bóveda —el candado es de la consola, un perfil bloqueado sigue sirviendo a sus
agentes— aplicada a otra máquina.

## 3. Lo que hace la réplica barata: **no puede leer lo que guarda**

Aquí es donde el sellado por destinatario paga por sí solo. Desde v4, cada
variable privada está **cifrada a la llave del aparato que la va a consumir**, y
el vault es un cartero que reparte sobres que no puede abrir.

La consecuencia es enorme para esto: **una réplica tampoco puede abrirlos.**

Así que una réplica se puede poner **donde sea** sin perder confidencialidad: otro
VPS alquilado, la máquina de un socio, un bucket de R2, un disco en casa. No hay
que confiar en el sitio, porque el sitio no puede leer nada. El acta, por su parte,
es pública y autoverificable por firma.

> Esto invierte el argumento habitual. En HashiCorp Vault replicar es delicado
> porque cada réplica descifra en memoria; aquí replicar es aburrido, que es
> exactamente lo que uno quiere de una réplica.

## 4. Qué puede y qué no puede una réplica

| | Réplica | Por qué |
|---|---|---|
| Servir el acta vigente y su cadena | **sí** | es pública y va firmada; el que la recibe la verifica |
| Entregar un sobre sellado a quien lo pide | **sí** | el sobre ya está sellado al destinatario; la réplica solo lo transporta |
| Servir certificados **ya emitidos** | **sí** | son papeles firmados, no secretos |
| **Sellar un acta nueva** (admitir, revocar, cambiar permisos) | **NO** | D4: un solo sellador |
| **Emitir un certificado nuevo** | ver §5 | necesita firma de la maestra |
| **Aprobar** una entrega de clave privada | **NO** | eso es del teléfono (`+aprueba`), y así debe seguir |
| Abrir un sobre | **no puede**, aunque quisiera | no tiene la llave del destinatario |

## 5. El problema de verdad: renovar certificados

Servir sobres viejos es fácil. Lo que no se puede replicar sin más es **firmar
papeles nuevos**, y los certs caducan a los 30 días.

**Salida: CA raíz fuera de línea, intermedia en línea.** Es lo que hace cualquier
PKI seria desde hace treinta años, y aquí encaja sin inventar nada porque **la
delegación por capacidades ya existe**:

- La maestra emite a la réplica un cert delegado con una capacidad **estrecha**:
  `renew-certs` y nada más. No admite aparatos, no cambia permisos, no toca el acta.
- Ese cert **caduca antes que los que emite** (p. ej. réplica 30 días / certs que
  emite 7 días), para que una réplica comprometida tenga una ventana corta y se
  apague sola si la maestra no vuelve.
- Renovar **no es admitir**: solo alarga la vida de un miembro **que ya está en el
  acta vigente**. Una réplica no puede meter a nadie nuevo, que es la única
  operación que de verdad importa proteger.

Con eso, la maestra puede estar apagada semanas sin que caduque nada, y sigue
siendo la única que decide *quién* pertenece.

## 6. Sincronización

Las réplicas **son miembros del acta**, con una capacidad `replica`. Se enrolan
como cualquier aparato y hablan por el proxio, que ya está federado.

- **Empuje:** tras cada sellado o cada escritura de secreto, la maestra manda el
  acta nueva y los sobres afectados a cada réplica. Firmado, como todo.
- **Arrastre al arrancar:** la réplica pide el acta vigente a la maestra y a las
  otras réplicas antes de responder a nadie.
- **Anti-rollback: ya está construido.** El pin de `maxSeq` (§2.3) es exactamente
  el mecanismo — una réplica restaurada de un respaldo viejo presenta un `seq`
  menor y **la rechazan los propios servicios**. No hay que escribir nada nuevo.

### 6.1. Consecuencia que hay que aceptar: el oráculo de frescura deja de ser opcional

`acta-de-perfil.md` §2.4.2 dejó el oráculo de frescura **diferido**, con este
argumento: *«el conflicto que resuelve exige restaurar un respaldo viejo del
vault, cosa poco frecuente»*.

**Con réplicas ese argumento se cae.** Una copia atrasada deja de ser un accidente
raro y pasa a ser el estado normal del sistema durante unos segundos, cada vez.
Y peor: un aparato revocado puede ir a buscar deliberadamente la réplica más
retrasada, que es justo la ventana de rollback (R1) que el oráculo cerraba.

Así que: **el oráculo de frescura es un prerrequisito de las réplicas, no un
extra.** Si se construyen las réplicas sin él, se está construyendo el ataque.

## 7. La réplica más barata ya existe

**El aparato.** `startDeviceVault` ya hace que un dispositivo sostenga parte de
esto, y el patrón del ecosistema es justo ese: el aparato cumple el rol cuando no
hay pieza dedicada. Formalizar «cada aparato guarda el acta y los sobres que le
tocan» da **N réplicas gratis**, sin comprar una máquina.

Y en el suelo del todo está la réplica fría: **las 24 palabras impresas** más una
exportación cifrada. No sirve para disponibilidad, sirve para no perderlo todo.

## 8. A quién le pregunta un servicio

La opción simple, y la recomendada: **el servicio lleva una lista de pubkeys de
bóveda y las prueba en orden.** No exige tocar el proxio y se depura mirando un
`.env`.

La alternativa —dirigirse al *perfil* y que el proxio entregue a cualquier miembro
con capacidad `replica` que esté conectado— es más elegante y pide enrutado
«a cualquiera de estos», que hoy no existe. Se deja para después, si molesta.

## 9. Fases

1. **Oráculo de frescura** (§2.4.2 de `acta-de-perfil.md`). Va primero: sin él las
   réplicas son un agujero.
2. **Réplica de solo lectura**: capacidad `replica`, empuje del acta y los sobres,
   servir. Sin renovación de certs.
3. **Lista de bóvedas en el cliente** (`@dotrino/vault/env`), con reintento en orden.
4. **Renovación delegada** (§5), con la capacidad estrecha y el cert corto.
5. **El aparato como réplica** (§7), que es lo que lo vuelve gratis para todos.

## 10. Estado

**Nada implementado.** Hoy hay una sola bóveda, en `74.208.234.139`, y si se cae
los servicios esperan en silencio.
