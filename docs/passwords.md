# La bóveda de contraseñas dentro del vault

> Estado: **cableado** (2026-08-26). 10 tests propios, 259 en la suite del vault.

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

## Cómo usarlo

```bash
dotrino-vault passwords <ID> on      # ese aparato puede pedir contraseñas
dotrino-vault approval <ID> on       # y además te pedirá el visto bueno en el teléfono
```

Tras el primer `on` hay que **reiniciar el vault**: el escritorio solo se levanta si hay
algún aparato autorizado, porque sin nadie a quien responder crear la llave sería crear
un secreto que nadie pidió.

## Las cuatro piezas, y cómo quedaron

1. **Dónde viven las entradas.** `passwords.json` en el directorio del perfil, cifrado
   en reposo con `atRestFor(dir)` — el mismo patrón que `approval.json`. Los valores van
   además cifrados con la CEK, así que abrir el archivo tampoco enseña las contraseñas.
   Solo los **sitios** quedan en claro dentro: hacen falta para emparejar sin abrir nada.
2. **La llave (CEK).** Nace en el primer uso y vive en ese mismo archivo. Aquí no se
   envuelve a cada aparato, y no es un descuido: **ningún aparato abre la bóveda**, piden
   de a una y el vault responde.
3. **El permiso.** `memberCanReadSecrets` **no servía**: exige un `cn` y eso es para
   servicios, no para los aparatos del usuario. Se usa una **lista de esta bóveda**, como
   `approval.json`, con el mismo argumento que ya está escrito ahí: *es ella la que
   entrega*. Y hacen falta **las dos** condiciones — estar en la lista **y** seguir en el
   acta —, así que revocar un aparato le corta esto también, sin acordarse de dos sitios.
4. **La aprobación en dos tiempos.** Un `Map` de `id → resolve` y una rama en
   `handleApproval` **antes** de `resultFor` (que asume un cajón y una `ek`). Con
   vencimiento propio: si nadie contesta en 5 min, la promesa se resuelve en «no» en vez
   de quedarse colgada.

Y una quinta que apareció al hacerlo: `isAllowed`/`encPubOf` del responder son
**síncronos** —se llaman por cada mensaje— así que el acta se lee en **caché refrescada
cada 5 s**, no con un `await` por mensaje. Revocar tarda eso en surtir efecto, no un
reinicio.

## Lo que no cambia

El protocolo. Un aparato pide una credencial por dominio y recibe esa sola; `list` no
existe en remoto, ni siquiera para la consola.
