# El respaldo de la bóveda

> Pedido por el dueño el 2026-10-16: *«El vault debe tener un proceso para hacer un backup
> encriptado con password de todo; como las llaves son de dispositivo, solo se respalda el
> contenido de sobres y cajones»*, *«debe haber así mismo un proceso para importar, la
> importación debe tener manejo de conflictos»*, *«obviamente son procesos de bóvedas
> abiertas»* y *«el proceso de backup debe ser de todo o solo por cajón: de repente quiero
> mover un cajón de un vault a otro»*.

Implementado en `lib/src/core/backup.js` (el archivo, el plan y los choques, exportado como
`@dotrino/vault/backup`), en `lib/src/core/vault.js` (`backupDrawers`, `exportBackup`,
`planBackupImport`, `importBackup`), en el CLI (`dotrino-vault backup`) y en la TUI (tecla `o` en
Bóvedas), que la ventana de escritorio pinta igual. Uso: wiki, *Bóveda → Respaldo*.

## 1. Qué lleva y qué no

| Va | No va |
|---|---|
| los **valores** de cada cajón: `ns:<scope>`, `dev:<aparato>` y el perfil `@me` | **ninguna llave**: ni la maestra, ni la de comunicación, ni la de sellado, ni las de los aparatos |
| si cada valor es público o privado | el **acta** (quién es de la cuenta y qué puede) |
| las **entradas** de la bóveda de contraseñas, enteras (campos, passkeys) | el **histórico** de cada variable: un respaldo es lo vigente |
| | los envoltorios (`wraps`) y las firmas de los sobres |

**Por qué valores y no sobres.** Un sobre va envuelto a los aparatos de ESTA cuenta y a su copia
de recuperación. En otra bóveda no lo abre nadie, y mover un cajón de una bóveda a otra es la
mitad de lo que esto tiene que hacer. Así que al exportar se abre cada valor con la copia de
recuperación y al importar se vuelve a sellar con las llaves de la bóveda de destino, a los
aparatos de SU acta. Es lo mismo que hace la bóveda al convertir un almacén: rehacer sobres con
la bóveda abierta.

## 2. Las dos puntas son de bóveda abierta

Exportar es leer, y leer es lo que guarda la frase del perfil. Importar compara con lo que ya
hay, y comparar también es leer. Con la bóveda cerrada las dos se paran con `VAULT_LOCKED`; no se
intenta con la llave de la máquina.

## 3. El archivo

```json
{
  "format": "dotrino-vault-backup", "v": 1, "createdAt": 1760000000000,
  "kdf": { "name": "PBKDF2-SHA256", "iterations": 600000, "salt": "…" },
  "verifier": { "iv": "…", "ct": "…" },
  "box": { "iv": "…", "ct": "…" }
}
```

- La cripto es la de `@dotrino/passmanager` (`deriveKeyFromPassword`, `sealValue`): corre igual
  en Node y en el navegador, así que lo que exporta una de las tres versiones lo abre cualquiera.
- En claro solo van el formato y la fecha. **Ni los nombres de los cajones**: el archivo puede
  acabar en cualquier sitio.
- La contraseña tiene un mínimo de 12 caracteres. El archivo se ataca fuera de línea y sin
  freno, así que solo aguanta la longitud.
- El archivo lo **cierra el daemon**. Al volcado que lee el CLI llega ya cifrado, y nada pasa en
  claro por el disco.
- La contraseña **no se puede recuperar**. Sin ella el archivo no se abre.

Dentro de `box`:

```json
{ "v": 1, "createdAt": 1760000000000, "account": "<huella de la cuenta>",
  "drawers": [
    { "owner": "ns:proxy", "vars": { "TOKEN": { "value": "…", "public": false } } },
    { "owner": "dev:<pub>", "label": { "id": "AB12-CD34", "label": "proxy1" }, "vars": { … } },
    { "owner": "ns:@me", "vars": { "nickname": { "value": "…", "public": true } } },
    { "owner": "passwords", "entries": [ { "id": "…", "title": "…", "sites": [], "username": "…", "secret": "…" } ] }
  ] }
```

## 4. Todo, o solo algunos cajones

`exportBackup({ drawers })` e `importBackup(payload, { drawers })` aceptan la lista de cajones;
sin lista, van todos. Pedir uno que no existe es un error (`NO_SUCH_DRAWER`), no «nada que hacer».

**Mover un cajón** a otro nombre o a otro aparato: `map: { 'ns:geo': 'ns:geo-viejo' }`, o
`'dev:<pub A>': 'dev:<pub B>'`. Un cajón `dev:` cuyo aparato no está en el acta de destino **no
entra** (`no-device`). No se guarda «por si acaso»: nadie lo leería, y reaparecería solo si un
día entrara esa llave.

## 5. Choques

Importar **nunca pisa en silencio**. Primero se hace un plan (`planImport`), valor por valor:

| Estado | Qué es | Qué se hace |
|---|---|---|
| `new` | no existe en el destino | se escribe |
| `same` | existe con el mismo valor | nada |
| `conflict` | existe con otro valor | lo que se decida |

Las decisiones son dos: **`keep`** (se queda lo de la bóveda) y **`replace`** (gana el respaldo).
Valen para todos los choques (`onConflict`) o para cada uno (`decisions`, por
`"<cajón destino> <clave>"`), y la de cada uno manda. **Si queda un choque sin decidir, no se
escribe nada** y se devuelve la lista (`BACKUP_CONFLICTS`). Importar a medias y descubrir el
resto después es peor que no importar.

`importBackup` **rehace el plan** antes de escribir: no se fía de uno viejo. Si la bóveda
cambió entre el plan y la decisión y aparece un choque nuevo, se para.

**Un privado no se vuelve público por importar.** Si el destino ya lo tenía privado y el
respaldo dice público, se escribe privado y se avisa (`keptPrivate`). Es la regla de
`PrivateStaysPrivate`.

**Contraseñas.** Dos entradas son «la misma» si tienen el mismo `id`, o los mismos sitios y el
mismo usuario. Son iguales si coincide el contenido (sin contar fechas). Reemplazar escribe la
entrada del respaldo **con el id de la de aquí**, así que el almacén la cambia en su sitio.

## 6. Quién firma lo que se importa

Los valores de los cajones los firma la llave de sellado, como cualquier escritura. Las
contraseñas las firma la **maestra**, igual que al convertir (`sealPasswords`): las dos cosas
pasan con la bóveda abierta y son rehacer sobres, que es su segundo trabajo. Por eso la regla de
quién puede escribir una contraseña (`canWritePasswords`) acepta a la maestra de esta bóveda
además de los aparatos con `passwords`. Escribir no le da a la bóveda ninguna envoltura: sigue
sin poder leer nada.

## 7. Lo que se dice en voz alta

- **Contraseñas sin copia de recuperación.** Una entrada guardada antes de que existiera la
  copia de recuperación no la abre la bóveda, y no entra en el respaldo. El resumen lo cuenta
  (`passwordsUnreadable`) y el CLI lo avisa. Se arregla abriéndola una vez desde un aparato con
  `passwords`.
- **Las tres versiones.** El núcleo es el mismo en las tres. El binario lo tiene en el CLI, la
  TUI y la ventana; la pestaña y la extensión, en su pantalla (`three-versions.md`).
- **En la pestaña, solo la consola.** El iframe de identidad atiende a cualquier
  `*.dotrino.com`, y quien exporta elige la contraseña del respaldo: sería poder leerlo todo.
  Por eso los métodos de respaldo del iframe solo contestan al origen de la consola
  (`vault.dotrino.com`, y los de desarrollo).
