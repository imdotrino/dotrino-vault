# Los datos del perfil: firmados, y en tres clases

> Diseño abierto el 2026-09-03, a raíz de dos síntomas del dueño: *«estoy intentando
> editar la data del perfil pero no funciona, y en diferentes dispositivos se ve diferente
> data»*. Los dos salen de lo mismo, y la salida es la que él propuso: **los datos de la
> identidad tienen que ser objetos firmados por quien el acta autoriza a firmar por ella.**
>
> El acta (`acta-de-perfil.md`) dice **quién es** del perfil. Esto dice **qué guarda** ese
> perfil y cómo se pone de acuerdo entre aparatos. Son documentos hermanos.

## 1. Qué pasa hoy, y por qué son el mismo fallo

El perfil (`me`) vive **en cada aparato**. La bóveda guarda una copia. Al editar, el
aparato escribe en local y **empuja**; al arrancar, **jala**, y gana el que tenga la fecha
más nueva.

Tres cosas encadenadas, y ninguna se ve desde fuera:

1. **Editar exige la bóveda ABIERTA.** `src/vault.js`:

   ```js
   if (PROFILE_EDIT_METHODS.has(d.method) && isLocked()) {
     return reply(from, { type: MSG.ERROR, error: 'profile locked: unlock it…' })
   }
   ```

   Y la bóveda se cierra sola a los cinco minutos. O sea que casi siempre está cerrada
   cuando alguien edita.

2. **Ese fallo se traga.** `@dotrino/identity`, `vault/core.js`:

   ```js
   remoteStore({ …, method: 'profileSet', … })
     .catch(() => {}) // el vault puede estar apagado; se reintenta en la próxima edición
   ```

   Editas, se ve bien en pantalla, el empujón falla y nadie dice nada. Y «la próxima
   edición» se encuentra la bóveda cerrada otra vez.

3. **Gana el RELOJ, no la firma.** La reconciliación es por `updatedAt`, que es el reloj
   local de quien editó. Dos aparatos con la hora distinta resuelven al revés, y nadie se
   entera porque no hay nada que comprobar.

Junta las tres y sale exactamente el síntoma: editas en un aparato, el empujón falla en
silencio, ese aparato se queda con lo nuevo y los demás jalan lo viejo.

**Por qué el candado está ahí, que es la raíz.** La bóveda guarda el perfil **en claro**
(cifrado en reposo, pero legible por ella) y por eso se fía de él: aceptarlo es una
decisión suya, y una decisión de la bóveda exige tenerla abierta. Si lo que recibiera
fuera un objeto que **no puede leer ni falsificar**, aceptarlo no requeriría ninguna llave
suya — igual que ya pasa con los sobres de los secretos, que se escriben con la bóveda
cerrada desde el 2026-08-20.

## 2. Las TRES clases, y por qué son tres

Decidido por el dueño el 2026-09-03: *«hay un tercer sobre que es la información pública
de verdad, que sí es data en claro que se ve cuando alguien de afuera pide información del
perfil»*.

No es un detalle de implementación: **lo público no puede ir sellado a nadie**, porque
quien pregunta no tiene ninguna llave tuya. Un desconocido que mira tu tarjeta tiene que
poder leer tu nombre. Así que la clase decide **cómo se guarda**, y no al revés:

| Clase | Quién lo lee | Cómo viaja y cómo se guarda |
|---|---|---|
| **Privado** | solo tus aparatos | **sellado** a las llaves de cifrado de tus miembros. La bóveda lo transporta y no lo abre |
| **Compartido** | una persona concreta | **sellado a ella**. Le das tu teléfono a alguien, no al mundo |
| **Público** | **cualquiera que pregunte** | **EN CLARO**, y firmado. No hay a quién sellarlo |

Las tres van **firmadas**. Cambia quién puede leerlas, nunca si se puede comprobar de
quién son: un dato público sin firma es un dato que cualquiera puede inventar en tu nombre,
y eso es peor que no tenerlo.

> **Estado:** privado y público son lo que hace falta ahora y lo que se implementa.
> **Compartido no existe hoy** —la visibilidad es binaria: se ve o no se ve— y se deja
> escrito aquí para que la forma del registro no tenga que cambiar cuando toque.

## 3. La forma: **un dato es un sobre, idéntico al de una variable**

> Decidido por el dueño el 2026-09-03: *«cada dato es un sobre idéntico que guardar
> variables, el dispositivo es el que arma el paquete con los sobres»*.

No se inventa un formato nuevo. Un dato del perfil se guarda **exactamente como una
variable de un cajón** (`secretos-sellados.md`): una entrada sellada, su generación, su
firma, y un llavero con una envoltura por destinatario. La bóveda guarda sobres opacos y
**el aparato arma el perfil** con los que puede abrir — que es literalmente lo que ya hace
`openSealedBundle` con las variables.

Eso trae gratis todo lo que costó construir allí, y que aquí hace falta igual:

- **la bóveda no puede leerlos** (los privados), así que aceptarlos no es una decisión suya;
- **se reenvuelven solos al abrir la bóveda**, así que un aparato nuevo acaba viéndolo todo;
- **hay histórico y se puede revertir**;
- y **la deuda se ve**: un aparato sin envoltura sale marcado en vez de callarse.

Lo único que cambia respecto de una variable es **la clase**, y es lo que decide la forma
del sobre:

```js
// privado / compartido — igual que una variable de un cajón
{ key: 'telefono', class: 'private', gen: 7, e: { iv, ct }, seal, at, by }

// PÚBLICO — no hay a quién sellarlo, así que el valor va en claro… y firmado
{ key: 'nickname', class: 'public',  gen: 3, v: 'seyacat',  seal, at, by }
```

**Todo va firmado**, las tres clases. Cambia quién puede leer, nunca si se puede comprobar
de quién es: un dato público sin firma es un dato que cualquiera puede inventar en tu
nombre, y eso es peor que no tenerlo.

Y **el paquete lo arma el aparato**: la bóveda entrega los sobres que tiene, el aparato
abre los que le tocan y compone el perfil. Un tercero que pregunta recibe solo los
públicos, en claro, y comprueba su firma.

Tres cosas que esto arregla, y cada una es uno de los síntomas:

- **La bóveda no tiene que estar abierta.** Recibe un sobre firmado por un miembro que el
  acta nombra. Comprobar eso no necesita su maestra: es la misma comprobación que ya hace
  con cualquier mensaje. Y si es privado, además no puede abrirlo.
- **El conflicto lo resuelve el ORDEN.** Ver §4.
- **Quién puede editar lo dice el ACTA, y el permiso es `firma`** (decidido por el dueño,
  2026-09-03). Hoy está implícito en tener `guarda`, que es el permiso de escribir *cosas*
  en tu bóveda. Escribir tu identidad no es eso: es hablar por ti. Un servicio como el
  proxio tiene `guarda` para lo suyo y no debe poder cambiar quién eres.

## 4. El orden, y por qué no vale el reloj

`gen` por dato, y **solo sube** — el mismo nombre que en las variables, y a propósito:
es la misma idea y no conviene que se llame distinto. (`seq`, a secas, es el del acta.)
Quien escribe toma el que tiene y suma uno.

Un empate —dos aparatos escribiendo el mismo dato con la misma `gen`, que con relojes
distintos y sin conexión es normal— se rompe **igual en todas partes**: gana el de hash
menor. No es justo ni pretende serlo; es *determinista*, que es lo único que importa: los
dos aparatos llegan a la misma conclusión sin hablarse.

`at` se guarda, y sirve para enseñárselo a una persona («cambiado el martes»). **No decide
nada.** Es la misma línea que el resto del sistema: el acta no se ordena por reloj, los
certificados dejaron de caducar por reloj el 2026-08-31, y esto tampoco.

> Lo que esto NO promete: fusionar dos ediciones simultáneas del mismo dato. Una de las dos
> se pierde, y se pierde igual en todos los aparatos. Fingir otra cosa exigiría un CRDT por
> campo y un montón de máquina para un caso que casi no pasa — y cuando pasa, lo que la
> gente quiere es que no queden dos verdades, no que se mezclen.

## 5. Quién sirve el perfil público

Aquí está lo bueno, y encaja con lo que ya se construyó ayer.

Hoy el subconjunto público lo calcula **el aparato del dueño en el momento de preguntar**
(`publicMe()`). Si todos sus aparatos están apagados, **nadie puede ver su perfil**.

Con los datos públicos firmados y en claro, eso deja de ser cierto: los puede servir
cualquiera, porque quien los recibe **comprueba la firma** y no tiene que fiarse de quien
se los dio. En concreto:

- la **bóveda**, como ahora;
- un **replicador** (`replicas.md` §8.bis), que es literalmente para esto — reparte lo que
  la bóveda ya firmó, y un dato público firmado es el caso más fácil que hay: ni siquiera
  necesita ir sellado.

O sea que el trabajo de ayer paga aquí sin tocar nada: tu perfil público responde con tu
máquina apagada.

## 6. Lo que se rompe, dicho antes de romperlo

- **El `me` plano desaparece** como formato de intercambio. Lo que hoy es
  `{ telefono, telefonoVisible }` pasa a ser un registro con `class`. Hay que convertir lo
  que ya está guardado, y la conversión es de una sola dirección.
- **`profileSet` deja de recibir el perfil entero.** Recibe registros, uno por dato, y los
  valida por firma en vez de por permiso de escritura.
- **Un aparato viejo no entiende los registros.** Como toda la fase de desarrollo
  ([[dotrino-fase-desarrollo]]): se cambia limpio en los dos lados y se publica, sin
  retrocompatibilidad.

## 7. Fases

1. **El registro y su firma** en `@dotrino/identity`: crear, firmar, verificar, ordenar.
   Con pruebas del desempate, que es lo que nadie mira hasta que falla.
2. **La bóveda los acepta con el perfil CERRADO** y deja de gatear por `guarda`: pasa a
   comprobar la firma contra el acta. Aquí se cae el candado sobre editar, que es el
   síntoma que abrió todo esto.
3. **El empujón deja de tragarse el error.** Un `.catch(() => {})` en el camino de escribir
   es exactamente lo que `CLAUDE.md` prohíbe.
4. **Servir el público sin la bóveda**: por el replicador.
5. **Compartido con una persona** (§2), cuando haga falta.
