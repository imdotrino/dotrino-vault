# Abrir la bóveda desde el admin

> Decidido por el dueño el 2026-09-04: *«quiero que el admin pueda abrir la bóveda, hay que
> hacer un protocolo de comunicación para poder poner el password en el admin»*, y acotado
> por él mismo: **«no abrirlo, sino con la contraseña»**.
>
> Estado: **diseñado, sin implementar.**

## Qué se pide, y qué NO se pide

Poder **teclear la contraseña en el admin** y que la bóveda se abra, sin ir hasta su
máquina.

Lo que la acotación deja fuera, y es lo que hace que esto sea aceptable:

- **No** hay un permiso que abra la bóveda sin contraseña. Un aparato de administración
  robado no abre nada por sí solo.
- **No** hay una segunda copia de la llave que destapa la maestra en ningún sitio.
- **No** se convierte al admin en `sella`. Un sellador entra en TODOS los cajones (decidido
  el 2026-08-30) y eso es más de lo que se está pidiendo, no menos.

La contraseña sigue siendo **lo único que abre**. Lo único que cambia es dónde se teclea.

## Por qué el vault sigue haciendo el trabajo

La llave real es `scrypt(contraseña, salt del perfil, 32, {N:16384, r:8, p:1})`
(`profiles.js`, `adminKey`), y `unlock` lleva un **freno de fuerza bruta**: cinco fallos y
espera exponencial, persistida en el registro del perfil.

Es tentador que el admin derive la llave y mande solo eso —la contraseña no viajaría
nunca—. **No se hace**, por dos razones y la primera basta:

1. **El freno se quedaría fuera.** Un mostrador que acepta llaves derivadas es un oráculo
   sin límite: se prueban a ritmo de red. El freno vive donde vive el contador de intentos,
   y ese es el vault.
2. El admin necesitaría el `salt` del perfil para derivar, así que habría que repartirlo. No
   es catastrófico —un salt no es un secreto— pero es material que hoy no sale de la máquina
   y que ayuda a quien algún día se lleve el disco.

Así que **la contraseña viaja sellada y el vault hace el scrypt, comprueba el verificador y
aplica el freno**. El admin es un teclado, no una autoridad.

## El protocolo

Tres mensajes. El primero existe para que el segundo no se pueda reproducir.

### 1. `unlock.challenge` — el admin pide turno

```
admin → vault   { op:'unlock.challenge', publickey, ts }   + firma + cert
vault → admin   { nonce, encPub, ts, exp }                 + firma de sellado
```

- Va **firmado por el aparato y con su certificado**, y el vault exige que el acta le
  reconozca **`admin`**. Esto no es «cualquiera con la contraseña»: es *un aparato que
  admitiste* **más** la contraseña.
- `nonce` de un solo uso, con vencimiento corto (60 s). Se apunta como los nonces de las
  demás operaciones administrativas.
- `encPub` es la llave de cifrado a la que hay que sellar. Sale del acta, así que el admin
  la comprueba contra lo que ya tiene: no se fía de lo que llega.

### 2. `unlock.open` — la contraseña, sellada

```
admin → vault   { op:'unlock.open', nonce, sealed, ts }    + firma + cert
```

- `sealed` = la contraseña envuelta con `wrapForMember` hacia `encPub` (la misma cripto de
  los secretos sellados). **El proxio no cifra** (CONVENCIONES §4.1), así que ir sellado no
  es una mejora: es el requisito.
- El `nonce` va **dentro de lo sellado**, no solo al lado: si no, un sobre capturado se
  puede reenviar con un nonce nuevo cuando el atacante consiga uno.
- El vault: abre el sobre, deriva con `adminKey`, comprueba el verificador, **aplica el
  freno**, y abre. La contraseña se usa y se suelta; no toca disco ni queda en memoria más
  allá de la operación.

### 3. `unlock.result`

```
vault → admin   { ok, locked, tries?, waitMs? }            + firma de sellado
```

- Con `ok:false` va **el mismo freno que en local**: cuántos intentos van y cuánto hay que
  esperar. Callarlo dejaría al admin reintentando contra una puerta que ya no responde.

## Lo que se apunta en la bitácora

Abrir a distancia **se registra siempre**: qué aparato lo pidió y cuándo, y también los
intentos fallidos. Es exactamente el rastro que uno quiere el día que algo no cuadra, y la
bitácora está encadenada, así que no se puede reescribir sin que se vea.

## El riesgo que queda, dicho en voz alta

**La contraseña se teclea en una página web.** Lo que corra en esa página la ve. Es un
modelo de amenaza distinto del de teclearla en la máquina que ya tiene la maestra:

- a favor: el admin no carga **JavaScript de terceros** y vive en su propio origen, que es
  precisamente lo que hace que esto no sea temerario;
- en contra: una dependencia comprometida en el build del admin es tu contraseña. Hoy, esa
  misma dependencia comprometida no puede abrirte la bóveda.

No se compensa con criptografía: se compensa con la cadena de suministro del admin
(`.npmrc` con `ignore-scripts`, versiones exactas, SBOM) y con que **la contraseña siga
siendo lo único que abre**, que es la acotación del dueño y la razón de que esto sea
defendible.

## Lo que NO cambia

- El candado sigue siendo **de la consola**: con el perfil cerrado los agentes ya
  emparejados siguen recibiendo sus secretos. Abrir a distancia no cambia eso.
- La maestra sigue teniendo **dos trabajos** y ninguno más.
- Con el perfil cerrado no se firma nada. Abrirlo a distancia no crea una vía nueva de
  firmar: crea una vía nueva de **teclear la contraseña**.
