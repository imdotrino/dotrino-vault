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
| Servir el acta vigente y su cadena **a un miembro** | **sí** | va firmada, y el que la recibe la verifica |
| Entregar un sobre sellado **a quien el acta deja leer ese cajón** | **sí** | el sobre ya está sellado al destinatario; la réplica solo lo transporta |
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

### Se comprueba quién pregunta (corregido el 2026-09-04)

Durante un día no se comprobaba, y conviene dejar escrito por qué, porque el razonamiento
que lo dejó así es correcto y aun así llevaba a un agujero.

El razonamiento: *un sobre va cerrado a su destinatario, así que a quien no le toque le
llega algo que no puede abrir; un replicador que decidiera quién lee sería un replicador
del que hay que fiarse, y la gracia es que no haga falta.* Todo eso sigue en pie.

Lo que se pasaba por alto: dentro de la respuesta **también viaja el acta**, que no es un
sobre — es el inventario de máquinas del dueño, y la bóveda no se lo enseña ni a un
servicio de la casa. Así que bastaba nombrar un cajón y una llave de aparato, sin firmar
nada y sin haber estado nunca en la cuenta, para sacarlo entero. Y de paso quedaba texto
cifrado en manos de cualquiera, para siempre y sin rastro de quién se lo llevó.

Se comprobó en vivo antes de arreglarlo: `dotrino-test/smoke/replica.mjs`, escenario **«a
un DESCONOCIDO el replicador no le da ni el cajón ni el acta»** — llave recién hecha, sin
papel, sin firma. Ahora el replicador mira lo mismo que mira la bóveda: **frescura, el
papel (`verifyChain` contra los selladores que nombra su acta) y `memberCanReadSecrets`**.
No costó ni un mensaje nuevo ni una llave más: la petición **ya viajaba firmada y con
papel** desde `fetchSecrets`; aquí no se miraban.

Y no lo convierte en alguien de quien haya que fiarse, que era el miedo legítimo: si
mintiera diciendo que sí, el sobre sigue sin abrirse; si mintiera diciendo que no, es una
caída — y una caída es exactamente lo que un replicador puede costar.

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

## 11. DECIDIDO (2026-10-26): las bóvedas son CLONES, y comparten la sincronización con el replicador

> El dueño: *«las vaults deben tener un sistema de sincronización: cuando una cambia debe
> notificar a las otras y actualizar, cuando una despierta debe pedir a las otras también
> actualizaciones; en teoría todas deben tenerlo todo, ser clones»*. Y: *«la diferencia entre
> una vault y una réplica es que la vault puede firmar un acta; de ahí deben compartir el
> sistema de sincronización»*.

### 11.1. Lo que lo destapó

La bóveda de Lambda de Seyacat (`Mode: join`, vaultd 0.176.2) no podía firmar **nada** de lo
que sirve: `this vault has no sealing key named by the record: it cannot serve`. El acta nombra
**una** llave de sellado (`sealPub`), la estrena quien sella esa acta, y la #58 la selló el PC.
Todo lo que sale firmado por `sealOrFail` —entregar secretos, la lista de pedidos, aprobar,
denegar, avisar de una actualización— solo lo podía servir el PC. Con el PC apagado, la segunda
bóveda no servía, que es justo para lo que se paga. Y al abrirse, una bóveda que no tiene la
`sealPub` del acta la rota (`vault.js`, arranque): las dos se la habrían ido quitando.

Además, entre dos bóvedas que sellan solo viajaba el acta. Lo demás (cajones, pedidos, avisos)
se quedaba en la que lo escribió.

### 11.2. Una pieza, dos papeles

Bóveda y replicador son **el mismo nodo de sincronización**. La única diferencia es que la
bóveda tiene maestra y puede sellar el acta; el replicador no.

| | Bóveda | Replicador |
|---|---|---|
| Recibe y empuja cambios | sí | sí |
| Al despertar pide lo que le falta | sí | sí |
| Sirve lo que tiene | sí | sí |
| Sella el acta / fabrica sobres nuevos | sí (abierta) | nunca |

**Hermanas:** las bóvedas y los replicadores de la cuenta, sacados del acta (miembros con
`cn: 'vault'`, los que sellan y los `replica`). No hay lista aparte que mantener.

### 11.3. Qué se clona y qué no

| Se clona (los datos) | NO se clona (las llaves, D1) |
|---|---|
| el acta y su cadena | la maestra (`key.json`, `identity.json`) |
| los cajones (`secrets.json`): sobres ya sellados a su destinatario | la llave de comunicación (`commkey.json`) |
| pedidos y avisos (`notices.json`, `exnotices.json`) | las llaves de sellado (`sealkeys.json`) |
| las máquinas (`machines.json`) y quién recibe avisos (`notifiable.json`) | el cifrado del disco (`atrest.*`) |
| los ajustes (`approve.json`, `prefs.json`) | |
| el respaldo del store (`threads.json`) | |

Clonar los datos no abre nada: un sobre va cerrado a quien lo consume, y guardarlo no exige
abrirlo. Por eso **una bóveda cerrada también sincroniza**, igual que un replicador.

### 11.4. Cómo viaja

- **Empuje al cambiar.** Tras cada cambio, el nodo lo manda a sus hermanas, firmado. Es
  `pushToReplicas` generalizado a todas las hermanas y a todos los datos de §11.3. Se juntan los
  cambios de unos segundos en un empujón: cada empujón timbra a una Lambda dormida y la despierta.
- **Arrastre al despertar.** El nodo dice a sus hermanas por dónde va y ellas le mandan lo que le
  falte. Es el `replica.ack` → `catch-up` de hoy, en las dos direcciones.
- **Primero se ponen de acuerdo, después reparten** (dueño, 2026-10-26: *«las bóvedas primero
  deben ponerse de acuerdo entre ellas antes de andar mandando actas»*). Una bóveda que sella o
  adopta un acta se la empuja antes a sus hermanas y solo después la anuncia a los aparatos. Y
  una que despierta se pone al día con las hermanas ANTES de contestar a nadie. Lo que lo pidió:
  la Lambda despertó en la #58, le llegaron la #60 y la #59 a la vez, y por una carrera al
  adoptar se quedó en la #59 (identity 0.129.2 pone las adopciones en fila); los aparatos ya
  tenían papel de la #60 y ella les contestaba «stale-record».
- **Conflictos: gana el último cambio.** Cada cambio lleva hora y nodo. Si dos hermanas cambiaron
  lo mismo sin verse, gana el más reciente; el perdedor se apunta en la bitácora y se avisa a los
  aprobadores. El acta no entra aquí: sigue con su regla (`seq`, y `canAdopt` para el empate).

### 11.5. Quién firma lo que se sirve: cada bóveda, con SU llave de sellado, y el acta las nombra todas

**Decidido (dueño, 2026-10-26): *«ambas son master»*, *«son clones y pueden hacer lo mismo, y se
sincronizan»*, y *«la bóveda antigua puede saber la pública de sellado de la otra bóveda, así que
le puede presellar»*.**

Ninguna bóveda es la principal. Cada una tiene su llave de sellado, que no sale de su máquina (D1).
Su **pública** sí viaja con la sincronización, así que la bóveda que sella un acta nombra en ella
la llave de sellado de **cada** hermana: la suya recién estrenada y la vigente de las demás. Así,
nada más sellarse el acta, todas pueden firmar lo que sirven y los sobres que escriben, sin que la
otra tenga que abrirse ni sellar.

- **El acta pasa de una `sealPub` a una por bóveda**, con su registro de tramos (`sealKeys`) por
  bóveda, para que los sobres viejos sigan verificando (§8.9 de `secretos-sellados.md`).
- **La firma dice de qué bóveda es** (`seal.by` junto a `seal.seq`), y quien verifica busca la
  llave de ESA bóveda en el acta de ese `seq`.
- **Cada bóveda rota solo la suya**, al sellar. La de una hermana no la puede rotar (no tiene la
  privada): la nombra tal como la conoce.
- **Desaparece la rotación cruzada** del arranque: una bóveda que se abre ya no rota porque «el
  acta no nombra la mía», porque el acta sí la nombra.
- Cualquier bóveda abierta puede hacer lo que haga otra: sellar el acta, admitir, revocar,
  escribir variables y fabricar sobres. Lo hecho se sincroniza (§11.4).

### 11.6. Lo que sigue en pie

- **D1:** las llaves no viajan. Clonar es de datos.
- **El oráculo de frescura (§6.1)** sigue siendo prerrequisito: una hermana atrasada es el estado
  normal unos segundos.
- **Un replicador no fabrica sobres** (§8.bis, limitación 2): uno para un miembro nuevo lo hace la
  primera bóveda que se abra, y desde ahí se clona a todas.

### 11.6.bis. Al admitir otra bóveda, la que admite le hace los sobres y se los manda (dueño, 2026-10-26)

> *«El momento que una bóveda admite otra bóveda debe hacer los sobres de los cajones para que lo
> use y se los envía; no hace falta abrir la bóveda remota.»*

Admitir es sellar el acta, así que la bóveda que admite **ya está abierta** y tiene la llave de cada
cajón. En ese momento envuelve cada cajón a la `encPub` de la bóveda nueva y le manda los sobres
junto con el acta, por el mismo empuje de §11.4. La nueva no tiene que abrirse para nada: guarda
lo que le llega, como cualquier hermana cerrada.

Hoy ya se le envuelven (`cosealerMembers` en `recipientsOf`), pero los sobres se quedan en el disco
de la que admite: no le llegan a la nueva. Y si la nueva no trae `encPub` al darse de alta, no hay a
dónde envolver: el alta de una bóveda la tiene que traer, o se para y se dice.

### 11.7. Fases

1. Una llave de sellado por bóveda en el acta (§11.5): `@dotrino/identity` (acta), la bóveda
   (firmar con la suya, nombrar las de las hermanas) y quien verifica (`@dotrino/vault/service`,
   el replicador). Arregla la Lambda de Seyacat por sí solo.
2. El nodo de sincronización común: empuje y arrastre entre hermanas, de los datos de §11.3,
   empezando por el alta (§11.6.bis): la que admite manda los sobres a la nueva.
3. El replicador pasa a usar ese mismo nodo, y `pushToReplicas` desaparece.
