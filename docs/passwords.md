# La bóveda de contraseñas dentro del vault

> Estado: **cableado** (2026-08-26). Emparejamiento y permiso unificados con el resto del
> ecosistema el 2026-08-27. 12 tests propios, 266 en la suite del vault.

## Qué es

`dotrino-passmanager serve` (repo `dotrino-passmanager`) es la bóveda de contraseñas en
su versión mínima: bóveda propia, aprobación por consola, bitácora propia. Este módulo
es lo mismo **dentro del vault**, que ya tiene lo que allí había que improvisar:

| | En `passmanager serve` | En el vault |
|---|---|---|
| quién puede pedir | el **acta** (la misma pieza, `@dotrino/vault`) | el **acta** |
| aprobación | una pregunta en la consola | el **teléfono** (`caps +aprueba`) |
| bitácora | un `console.log` | `activity.log`, la misma de firmas y enrolamientos |

Las dos son bóvedas del ecosistema: los aparatos entran por el enrolamiento de siempre y
lo que cambia es la disponibilidad, no el modelo. La diferencia real del daemon es que
sigue encendido con el navegador cerrado.

El protocolo **no cambia**: un aparato pide una credencial por dominio y recibe esa
sola. `list` no existe en remoto.

## Cómo usarlo

```bash
dotrino-vault pair --scope contrasenas   # conectar el gestor, ya con su permiso
dotrino-vault caps <ID> +contrasenas     # o dárselo después a un aparato que ya está
dotrino-vault approval <ID> on           # y que además te pida el visto bueno en el teléfono
```

**No hay códigos que pegar.** El gestor se empareja como cualquier otro aparato:
invitación de la bóveda, seis caracteres que muestra el aparato y se teclean aquí, cert
firmado por la maestra y entrada en el acta.

El mostrador se levanta **en cuanto** alguien tiene el permiso, sin reiniciar el vault.
Si no lo tiene nadie no se levanta, porque sin a quién responder crear la llave sería
crear un secreto que nadie pidió.

## Las cuatro piezas, y cómo quedaron

1. **Dónde viven las entradas.** `passwords.json` en el directorio del perfil, cifrado
   en reposo con `atRestFor(dir)` — el mismo patrón que `approval.json`. Los valores van
   además cifrados con la CEK, así que abrir el archivo tampoco enseña las contraseñas.
   Solo los **sitios** quedan en claro dentro: hacen falta para emparejar sin abrir nada.
2. **La llave (CEK).** Nace en el primer uso y vive en ese mismo archivo. Aquí no se
   envuelve a cada aparato, y no es un descuido: **ningún aparato abre la bóveda**, piden
   de a una y el vault responde.
3. **El permiso.** `memberCanReadSecrets` **no servía**: exige un `cn` y eso es para
   servicios, no para los aparatos del usuario. La primera versión salió del paso con una
   **lista de esta bóveda**, como `approval.json` — y eso resultó ser el error: quitar un
   aparato había que acordárselo en dos sitios, y el gestor acababa emparejándose por un
   camino propio para poder entrar en esa lista.

   Hoy es una **capacidad del acta**, `passwords` (scope `vault:passwords`), como
   `admin` o `approve`: se concede al emparejar o después, se quita sola, y revocar el
   aparato la retira con todo lo demás. Un solo registro y un solo acto.
4. **La aprobación en dos tiempos.** Un `Map` de `id → resolve` y una rama en
   `handleApproval` **antes** de `resultFor` (que asume un cajón y una `ek`). Con
   vencimiento propio: si nadie contesta en 5 min, la promesa se resuelve en «no» en vez
   de quedarse colgada.

Y una quinta que apareció al hacerlo: `isAllowed`/`encPubOf` del responder son
**síncronos** —se llaman por cada mensaje— así que el acta se lee en **caché refrescada
cada 5 s**, no con un `await` por mensaje. Revocar tarda eso en surtir efecto, no un
reinicio.

Y una sexta, que costó un rato encontrar: **el cliente del vault es uno solo y no sabía
abrir sobres.** El protocolo de la CA viaja en claro a propósito (un enrolamiento es
público hasta que hay cert), así que el cliente se creaba sin sellado — y las peticiones
del gestor, que sí van selladas, entraban y se tiraban sin una línea en el log. Se le
pone un adaptador de sellado (`updateConfig({ sealing })`) cuya marca es la del gestor y
solo la suya, para no tragarse el protocolo del vault. Hay un test que lo fija.

## Lo que no cambia

El protocolo. Un aparato pide una credencial por dominio y recibe esa sola; `list` no
existe en remoto, ni siquiera para la consola.
