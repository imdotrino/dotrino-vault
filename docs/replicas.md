# Réplicas de la bóveda (diseño — no implementado)

> Anotado el 2026-08-30, a raíz de comparar la bóveda con un KMS. **Hoy la bóveda
> es una sola máquina: sin réplica, sin relevo y sin SLA.** Un KMS de nube es
> multi-zona. Esto es el plan para cerrar esa parte.

## 1. El problema, y por qué duele más de lo que parece

Si la máquina del vault está apagada, un servicio que necesita su secreto **no
falla: espera**. `waitForSecrets` reintenta para siempre, y `secretos-sellados.md`
ya lo dejó escrito como «el error que más caro salió» — porque desde fuera no se
distingue de que todo va bien.

> **CORREGIDO el 2026-09-02.** Aquí decía que los certificados duran 30 días y que una
> bóveda apagada un mes deja el ecosistema entero caducado. **Ya no es cierto**, y llevaba
> escrito lo bastante como para hacer equivocarse a quien leyera solo este documento.
> Desde `@dotrino/identity` 0.73 (decisión del dueño, 2026-08-31) un certificado lleva
> `seq` en vez de `exp`: **no caduca por reloj, muere cuando cambia el acta**. Los papeles
> del modelo viejo se aceptan hasta el **2026-10-01** y ya no se emiten
> (`vault/capabilities.js`, `LEGACY_CERTS_UNTIL`).

Lo que sí sigue en pie: si la máquina está apagada, **no se puede cambiar el acta**. Nadie
admite un aparato, nadie revoca, nadie cambia un permiso. Lo ya emitido sigue funcionando
—ese es el cambio—, así que lo que se pierde es **administrar**, no el acceso.

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

> **Cómo se lee esto desde el 2026-09-02, que parece una contradicción y no lo es.** §1.bis
> dice que hay DOS selladores y esta sección dice que una réplica no sella jamás. Las dos
> son ciertas porque hablan de **piezas distintas** (§8.bis): una segunda **bóveda** tiene
> maestra y sella —es el multivault, y se conserva—; un **replicador** no tiene maestra y no
> sella nunca. Lo que sigue en pie sin matices es D4: **un acta la sella uno**, y por eso
> dos selladores no se abren a la vez.

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

## 5. ~~El problema de verdad: renovar certificados~~ — DESAPARECIÓ

**Esta sección entera está obsoleta desde el 2026-08-31, y se deja tachada en vez de
borrada porque su razonamiento explica por qué el diseño de abajo es más barato de lo que
parecía.**

Decía que lo que no se puede replicar es firmar papeles nuevos, porque los certs caducaban
a los 30 días, y proponía una CA intermedia con una capacidad estrecha `renew-certs`.

**Ya no hay nada que renovar.** Un certificado lleva `seq` y muere cuando cambia el acta,
así que la maestra puede estar apagada meses sin que se caiga nada. La CA intermedia sobra.

Y de paso resuelve mejor lo que aquella propuesta buscaba: quitarle un permiso a un aparato
surte efecto **al instante** —el acta sube de `seq` y su papel deja de valer— en vez de
esperar a que venza una renovación.

**Lo que empeora, y hay que decirlo:** el tope de 30 días era además el freno de la ventana
de rollback (R1 en `acta-de-perfil.md`). Sin él, una política vieja **ya no caduca sola**, y
lo único que acota R1 es el pin de `maxSeq`. Para quien ya conoce la cuenta eso basta; para
un aparato que llega nuevo, no hay con qué comparar. Es la razón por la que §6.1 dice que el
oráculo de frescura es un **prerrequisito** de las réplicas, y ahora lo es más que cuando se
escribió.

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

## 8.bis DECIDIDO (2026-09-02): el modo `--replica`, y NO sustituye al multivault

> El dueño, sobre lo de abajo: *«esta solución es la ideal»*. Y acto seguido:
> *«lo del multivault es otra cosa, esa característica hay que conservarla»*.

**Son dos piezas distintas y las dos se quedan.** Confundirlas sería deshacer lo del
2026-08-30:

| | **Segunda bóveda** (§1.bis) | **Replicador** (esto) |
|---|---|---|
| Tiene maestra | **sí** | **no**, y se niega a crear una |
| Puede sellar el acta | sí, con `+sella` | **nunca** |
| Para qué está | que un desastre no se lleve la cuenta: sigue habiendo quien admita, revoque y cambie permisos | que la cuenta **responda** aunque tu máquina esté apagada |
| Qué cuesta que la comprometan | todo: sella en tu nombre | disponibilidad, nada más |
| Ejemplo | la bóveda en EC2 (`53F8-C1E8`, 2026-09-02) | cualquier sitio: un VPS alquilado, la máquina de un socio |

### Qué es

Un modo del mismo daemon. Arranca **sin maestra**, se niega a crear una, y rechaza toda
operación que selle. Lleva solo tres cosas:

- la **llave de comunicación**, para ser alcanzable (vive bajo la llave de máquina, así que
  no hay nada que abrir);
- el **acta vigente y su cadena**, que es pública y va firmada;
- los **sobres**, que ya vienen sellados a su destinatario.

Se enrola como cualquier aparato, con una capacidad estrecha, y queda en el acta como lo
que es. No abre nada, no firma nada, no decide nada: reparte lo que otro ya firmó y selló.

### Por qué es barato, y esto es lo que lo hace viable

**No hay que confiar en la máquina donde corra.** Un sobre está cerrado a la llave de quien
lo va a consumir, así que el replicador tampoco puede abrirlo (§3); y el acta la verifica
quien la recibe, por la firma. Que se la lleven cuesta disponibilidad y nada más.

De ahí sale lo demás: no hay maestra que proteger, así que no hay contraseña que gestionar
ahí, ni un sellador siempre abierto, ni razón para blindar esa máquina. Es lo contrario de
la de EC2, que **sí** hay que cuidar porque sella.

Y lo que lo volvió razonable fue el cambio del 2026-08-31: como un cert ya no caduca por
reloj, un replicador que solo sirve **no se pudre**. Antes habría aguantado lo que durase
el último papel.

### Las dos limitaciones, dichas antes de construirlo

1. **Un acta vieja es el ataque.** Un replicador atrasado presenta un acta donde un aparato
   revocado sigue siendo miembro. Para quien ya conoce la cuenta lo corta el pin de `maxSeq`,
   que ya está construido; **para un aparato que llega nuevo no hay con qué comparar**. Por
   eso el oráculo de frescura es prerrequisito (§6.1), y desde que el cert no caduca lo es
   más, no menos.
2. **Solo reparte los sobres que tiene.** Uno para un miembro que entró después de
   escribirse un valor **no existe** hasta que abras tu bóveda, porque fabricarlo exige
   abrir la llave del cajón. Un replicador está siempre tan al día como la última vez que
   abriste. No es un fallo: es la misma deuda que ya se ve en la consola.

## 9. Fases

1. **Oráculo de frescura** (§2.4.2 de `acta-de-perfil.md`). Va primero: sin él las
   réplicas son un agujero.
2. **Réplica de solo lectura**: capacidad `replica`, empuje del acta y los sobres,
   servir. Sin renovación de certs.
3. **Lista de bóvedas en el cliente** (`@dotrino/vault/env`), con reintento en orden.
4. **Renovación delegada** (§5), con la capacidad estrecha y el cert corto.
5. **El aparato como réplica** (§7), que es lo que lo vuelve gratis para todos.

## 10. Estado

**EL REPLICADOR ESTÁ CONSTRUIDO Y PROBADO** (2026-09-03, vault 0.98.0 · identity 0.79.0).
`dotrino-vault replica enroll|run|status`, con el smoke `dotrino-test/smoke/replica.mjs`:
seis escenarios en tres máquinas, y el que importa mata la caja entera de la bóveda y
comprueba que el servicio sigue recibiendo su clave.

Lo que el smoke destapó, y que ninguna prueba de un proceso habría cazado:

1. **La bóveda solo empujaba al cambiar algo**, así que un replicador encendido después se
   quedaba vacío hasta el siguiente cambio. Faltaba el arrastre de §6, que este documento
   ya pedía: ahora el replicador dice por dónde va al conectarse y se le pone al día.
2. **El cliente solo le preguntaba a la bóveda.** Con ella apagada el mensaje no llegaba a
   nadie, así que un replicador no servía para nada por bien que guardara los sobres. Ahora
   lleva la lista y las prueba en orden (§8) — y la lista **sale del acta**, que llega
   firmada en cada respuesta, así que no hay un `.env` que mantener.
3. **Tres confusiones entre «conexión» y «llave»**, del tipo que no falla ruidosamente:
   `sendByPubkey` con un identificador de conexión no da error, se va a la nada y quien
   preguntó espera el plazo entero. Y comparar `from` con una llave del acta rechazaba a
   todo el mundo — que es el lado bueno de equivocarse.

**Dos condiciones que no se esconden**, y las dos son el precio de no tener el oráculo de
frescura (§6.1):

- **Un aparato que nunca vio la cuenta no le cree a un replicador.** Sin `maxSeq` pineado no
  hay con qué comparar un acta atrasada. Tiene que hablar con la bóveda una vez.
- **Un servicio aprende sus replicadores del acta.** Si añades uno, los servicios necesitan
  un intercambio con la bóveda —mientras todavía contesta— para enterarse. Añadir un
  replicador con la bóveda ya apagada no sirve de nada.

**El multivault se probó y se desmontó el 2026-09-02**, y sigue siendo la otra pieza: una
segunda bóveda tiene maestra y sella, un replicador no. Hoy la cuenta de Cepi tiene una
sola bóveda, la PC del dueño; si se cae no se puede cambiar el acta (admitir, revocar,
cambiar permisos), aunque lo ya emitido siga funcionando.

**El multivault se probó de punta a punta el 2026-09-02 y se desmontó el mismo día.** Una
bóveda en EC2 (`us-east-2`, contenedor con la clave del disco en AWS KMS) entró en la cuenta
como `53F8-C1E8` con `+sella`, y funcionó: la invitación salió de la PC, el código se tecleó
en la PC y al contenedor no se entró nunca. Se quitó del acta (#21) y se destruyó todo
porque **lo que hace falta es un replicador, no un segundo sellador** (§8.bis) — decisión
del dueño ese día. La cadena de selladores **no llegó a publicarse**: no había ningún
testigo anunciado en `dotrino.sealers`, así que la ventana con dos selladores no salió de
esa máquina.

Lo que dejó aprendido, y hay que tenerlo delante el día que se monte un replicador de
verdad: **el perfil de aquel contenedor no tenía contraseña**, así que su maestra quedaba
cerrada con la clave de la máquina —que allí era la del KMS, y el rol de la instancia la
desenvolvía—. O sea que era un sellador **permanentemente abierto**: cualquiera con una
shell ahí sellaba en nombre del dueño. Un replicador no tiene ese problema porque no tiene
maestra, y esa es exactamente la razón por la que es la pieza correcta para poner fuera.
