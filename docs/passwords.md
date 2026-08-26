# La bóveda de contraseñas dentro del vault

> Estado: **el módulo está escrito y probado (`src/passwords.js`, 7 tests); falta
> cablearlo al arranque.** Se paró a propósito antes de tocar `vault.js`: el enganche
> pasa por el arranque de la CA, que corre en producción, y hacerlo a ojo era el tipo de
> cambio que se descubre roto desde el otro lado.

## Qué es

`dotrino-passmanager serve` (repo `dotrino-passmanager`) es la bóveda de contraseñas en
su versión mínima: bóveda propia, aprobación por consola, bitácora propia. Este módulo
es lo mismo **dentro del vault**, que ya tiene lo que allí había que improvisar:

| | En `passmanager serve` | En el vault |
|---|---|---|
| quién puede pedir | una lista en un JSON | el **acta** |
| aprobación | una pregunta en la consola | el **teléfono** (`caps +aprueba`) |
| bitácora | un `console.log` | `activity.log`, la misma de firmas y enrolamientos |

El protocolo **no cambia**: un aparato pide una credencial por dominio y recibe esa
sola. `list` no existe en remoto.

## Lo que falta para cablearlo

Cuatro piezas, y ninguna está resuelta todavía:

1. **Dónde viven las entradas.** El módulo espera un `{ get, set }`. Lo natural es un
   `passwords.json` en el directorio del perfil, cifrado en reposo como el resto.
2. **La llave de la bóveda (CEK).** Tiene que nacer con el perfil, guardarse sellada y
   abrirse al desbloquear — y **cerrarse al bloquear**, como todo lo demás.
3. **El permiso.** `CAPS` de `@dotrino/identity` no tiene `passwords`, y añadirlo obliga
   a re-vendorizar el iframe de identidad. La salida sin tocar el pilar es tratarlo como
   un **namespace de secretos**: `Acta.memberCanReadSecrets(acta, pub, 'passwords')`, con
   el aparato llevando `vault:secrets:passwords` en su cert. Nada nuevo que inventar.
4. **La aprobación en dos tiempos.** El vault contesta «pendiente» y responde de verdad
   cuando el teléfono firma; el módulo espera una promesa. El puente es un `Map` de
   `id → resolve` y una rama en `handleApproval` **antes** de `resultFor`, que asume un
   cajón y una `ek`. Con vencimiento propio, para que la promesa no quede colgada si
   nadie contesta.

## Por qué no se hizo de una vez

Se escribió el enganche y se revirtió: referenciaba un almacén, una llave y un permiso
que no existen. En un módulo aparte eso lo caza un test; en el arranque del vault se
habría quedado en el `try/catch`, sin levantar nada y con un mensaje confuso — o peor,
funcionando a medias.

El módulo, mientras tanto, no estorba: nadie lo monta y sus tests corren solos.
