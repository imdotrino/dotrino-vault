# Abrir la bóveda desde el admin

> Pedido por el dueño el 2026-09-04 y acotado por él en la misma conversación. Implementado
> en `dotrino-vault` 0.110.0 y 0.111.0.

## El modelo

Con el perfil **cerrado** la consola se queda corta a propósito: `revoke` contesta
`vault-locked` porque reescribe el acta, y sellar el acta es de la maestra, que con el
candado echado no está en memoria.

Con sus palabras: *el admin abre la puerta en remoto, pero no tiene acceso a lo de dentro*.
Tres piezas, y ninguna sirve sola:

1. **Tú** pones la contraseña, en el admin.
2. **El admin** pide. Es un teclado y un botón, no una autoridad: **abrir no le da ningún
   permiso** que no tuviera ya por el acta. Lo único que cambia es que `revoke` pasa a
   atenderse, porque ahora hay una selladora abierta — la bóveda misma.
3. **La bóveda** hace el trabajo con su maestra, en su máquina.

## La contraseña del admin es OTRA

Distinta de la principal, y **no vale en la máquina**: `dotrino-vault unlock` sigue
aceptando solo la principal.

Eso es lo que la convierte en **dos factores**. Usarla exige llegar por el camino del
admin, y ese camino pide una petición firmada por un aparato que el acta reconozca con
`admin`, con su certificado. La contraseña secundaria filtrada, **sola, no abre nada**.

Se pone en la máquina, con el perfil abierto:

```
dotrino-vault profile admin-password        # ponerla o cambiarla
dotrino-vault profile admin-password rm     # quitarla
```

### Cómo se guarda: un segundo sobre de la MISMA llave

La llave del perfil es un `Uint8Array(32)` que sale de `scrypt(contraseña, salt)` y es lo
que destapa la maestra. Una segunda contraseña **no puede derivar una llave distinta** —
tiene que llegar a la misma. Así que en `profiles.json` el perfil gana
`kdf2 = { salt, wrapped }`, donde `wrapped` es **la llave del perfil cifrada con lo que sale
de la secundaria**. Dos puertas al mismo sitio.

- **Revocarla** = borrar `kdf2`. **Rotarla** = reemplazarlo. Sin tocar la principal.
- Si no existe, abrir a distancia **no está disponible**: se enciende a propósito.
- Ese sobre **no viaja nunca**: vive en el disco de la bóveda.

### Las dos puertas comparten el freno

Cinco fallos y espera exponencial, persistida. **El mismo contador para las dos**: si cada
una llevara el suyo, probar por un camino no frenaría el otro y el freno valdría la mitad.

## El molino lo hace el ADMIN

El primer diseño mandaba la contraseña y la derivaba la bóveda. El dueño preguntó lo
correcto —*«la bóveda sí llega a verla en claro en algún momento»*— y sí, la veía. Se
cambió, y el argumento que sostenía lo anterior resultó ser falso:

> «Si el admin deriva, el freno se queda fuera.»

No: **el freno cuenta intentos fallidos**, y los cuenta igual reciba una contraseña o un
resultado. Lo que cambia es quién paga el molino:

- **En la bóveda**: cada intento le cuesta CPU **a ella** y nada al que prueba — que además
  es una forma de ahogarla.
- **En el admin**: cada intento le cuesta un scrypt **al que prueba**, y la bóveda nunca ve
  la contraseña.

Lo que **no** mejora, y se dice: ese resultado de 32 bytes **vale tanto como la
contraseña**. Por eso viaja cifrado y por eso hace falta un aparato que firme.

Los parámetros (`salt`, `N`, `r`, `p`) son **públicos** —ya viven en el disco junto a los
datos— y la bóveda los manda para que el navegador derive **exactamente igual**. Viven en
una sola constante (`SCRYPT`, en `src/profiles.js`): si los dos lados se separan, la
contraseña «deja de funcionar» sin que nada diga por qué.

## El protocolo: dos mensajes, dos candados

```
admin → vault  { op:'unlock.begin', nonce, ts }   + firma + cert
vault → admin  { salt, N, r, p, len, ek }                          (la efímera vive 60 s)
admin → vault  { op:'unlock', nonce, enc, ts }    + firma + cert
vault → admin  { ok } | { error, code, tries, waitSec }
```

El sobre no se puede reproducir, y por **dos razones distintas**:

- **El nonce** hace que la bóveda **se niegue** a atenderlo dos veces. Es memoria: una lista
  de nonces usados que vive 10 minutos y se pierde al reiniciar.
- **La efímera** hace que **no se pueda** abrirlo dos veces. Se tira al usarla, así que ese
  sobre queda inabrible hasta para ella, incluso con el disco en la mano.

El nonce dice *«no quiero»*; la efímera dice *«no puedo»*.

**Y el nonce va DENTRO del sobre**, no solo al lado: si fuera solo por fuera, uno capturado
se reenvía con un nonce nuevo y el primer candado no serviría de nada.

### Por qué una efímera y no su llave de cifrado fija

La llave de cifrado de la bóveda **cede a la llave de la máquina** (modelo de amenazas
§4.2): cae con el disco. La maestra y `#recovery` **no** ceden, porque están bajo la
contraseña — así que **la contraseña es justo lo único que un ladrón de disco no tiene**.
Cifrarla con algo que el disco entrega sería regalársela a quien grabe el tráfico hoy y robe
el disco mañana.

## La ventana no se alarga desde la red

El auto-candado son **5 minutos**, y lo reinicia la actividad de la CLI y la TUI; lo que
llega por el proxio **no** lo alarga. Se deja así: abrir a distancia da una ventana corta
que se cierra sola. Si las operaciones del admin la alargaran, un admin comprometido
mantendría la bóveda abierta indefinidamente.

## El riesgo que queda

**La contraseña se teclea en una página web.** Lo que corra en esa página la ve — antes de
que el molino la convierta en nada. No se compensa con criptografía:

- a favor: el admin no carga **JavaScript de terceros**, vive en su propio origen, y sus
  dependencias van con versión exacta, `ignore-scripts` y SBOM;
- en contra: una dependencia comprometida en su build es esa contraseña.

Lo que lo hace defendible es la acotación del dueño: **lo que se teclea ahí no es la
cuenta**. Es una contraseña aparte, que sola no sirve, que no vale en la máquina, y que se
revoca borrando un sobre.

## Descartado, para que no vuelva

- **Un permiso que abra sin contraseña.** Un admin robado abriría la bóveda él solo.
- **Hacer sellador al admin (`+sella`).** Es *más* de lo que se pide: un sellador sella el
  acta y —decidido el 2026-08-30— entra en TODOS los cajones. En una página web, eso mete
  en el navegador llaves que abren todos los secretos.
- **Una cadena de sobres**: que la contraseña del admin abriera un sobre guardado en el
  admin que contuviera otra contraseña. La página que ve la primera abre ese sobre ella
  misma y se lleva la segunda: mismo resultado, un paso más, y una copia guardada que antes
  no existía.
- **Un «modo admin»** en el que la bóveda recordara con qué contraseña se abrió y se negara
  a ciertas cosas. Sobra: abrir no da permisos, así que el admin sigue teniendo lo que el
  acta le da. Y un modo es una comprobación que se puede olvidar en uno de quince
  mostradores; no tener la llave no es una comprobación.

## Pendiente

**Admitir aparatos a distancia** (`pair` / `approve`). Va aparte por decisión del dueño: es
la única operación que hace **crecer** la cuenta —una revocación se deshace, un aparato
ajeno dentro no— y merece su propia pasada, exigiendo la firma de un aparato con `approve`
por el mismo camino que ya existe para soltar claves privadas.
