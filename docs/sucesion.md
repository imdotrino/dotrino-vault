# Recuperar el control si la bóveda principal desaparece

> Planteado por el dueño el 2026-08-30: *«la idea del multivault sería poder recuperar
> el control si el vault master se pierde, con otro vault réplica. Hay que buscar el
> método de cómo se daría el control del acta a otro vault cuando el main desaparece, o
> mejor que ambos vaults puedan firmar ciertas cosas, como agregar dispositivos y aprobar
> salida de contraseñas.»*
>
> Diseño. **Solo una parte está implementada, y resulta que es la que ya funcionaba.**

## 1. La pregunta se parte en dos, y ahí está media respuesta

Las dos cosas que se pidieron —**añadir aparatos** y **aprobar la salida de
contraseñas**— parecen del mismo tipo y no lo son. La frontera que las separa es una
sola pregunta: **¿toca el acta?**

| Operación | ¿Cambia el acta? | ¿Pueden firmarla varios? |
|---|---|---|
| **Aprobar** la salida de una clave o contraseña | no | **sí — y ya funciona hoy** |
| Servir un sobre ya sellado | no | sí (es lo de `replicas.md`) |
| Renovar el cert de un miembro que ya está dentro | no: no cambia quién pertenece | sí, con una capacidad estrecha |
| **Añadir o quitar un aparato** | **sí** | **no: D4, un solo sellador** |
| Cambiar permisos de un miembro | sí | no |

Lo que no toca el acta es un **O lógico**: no hay estado compartido, ni número de
secuencia, ni forma de contradecirse. Ahí tener dos firmantes es gratis.
Lo que sí lo toca necesita **un solo escritor**, o se acabó la propiedad que hace que
todo esto funcione.

## 2. Aprobar desde una segunda bóveda: ya está hecho

Comprobado en `src/vault.js:684`. La aprobación no está atada a un aparato concreto:

```js
if (record && !Acta.memberCan(record, chk.device, 'approve')) { /* rechazar */ }
```

Es **cualquier miembro con la capacidad**. Así que una segunda bóveda (o un segundo
teléfono, o los dos) aprueba sin tocar una línea de código:

```
dotrino-vault caps <ID-de-la-segunda-bóveda> +aprueba
```

A partir de ahí, la salida de claves la puede autorizar quien esté despierto. **Si el
teléfono se pierde, la cuenta no se queda muda**, que era la mitad práctica del problema.

Lo único que hay que decidir a propósito: hoy vale **el primero que conteste**. Exigir
dos aprobaciones para lo más sensible sería otra cosa y no está escrito.

## 3. Añadir aparatos: por qué no puede haber dos selladores en vivo

`acta-de-perfil.md` §2.4 no deja lugar a interpretaciones: con **un sellador** (D4) y
**llaves intransferibles** (D1), dos actas legítimas con el mismo `seq` son
*criptográficamente imposibles*. De ahí sale lo mejor del diseño: **no hay merge, ni
precedencia, ni votación.**

Dos selladores en vivo tiran eso a la basura. En cuanto dos llaves pueden sellar el mismo
`seq` con contenido distinto, hay que decidir cuál gana — y eso es consenso distribuido,
con todo lo que arrastra. No es un cambio de una tarde: es otro sistema.

**Pero recuperar el control no exige dos selladores en vivo.** Exige un sucesor
**autorizado de antemano**, y eso es otra cosa.

## 4. Las tres formas, de menos a más cara

### A. Sucesor designado, a mano (break-glass) — **la recomendada**

El master, mientras está vivo, escribe en el acta: *«la llave S puede llegar a ser
selladora»*. S vive apagada en otro sitio: otra bóveda, otra máquina, una llave en un
cajón. No sella nada, no está en línea, no puede contradecir a nadie.

Cuando la principal desaparece, se enciende S y sella `seq N+1` nombrándose selladora.

**No hay bifurcación, y la razón ya está escrita en el propio documento del acta**
(§2.4.1): la promoción la autorizó *la firma del master anterior*, y entre dos actas del
mismo `seq` firmadas por la misma llave **gana la que le quita poder al firmante**. Es
exactamente el mecanismo que ya resuelve el caso del respaldo restaurado; aquí se usa a
propósito en vez de sufrirlo.

- **Coste:** un campo más en el acta y su comprobación. Pequeño.
- **Riesgo:** que la principal vuelva y no se haya enterado. Ya cubierto por §2.4.1 punto
  4 (*todo master, al arrancar, pide el acta vigente antes de sellar*) y por el pin de
  `maxSeq`.
- **Y el `profileId` no cambia**: es la pubkey de la génesis (D3), estable para siempre.
  Cambia quién sella, no quién es la cuenta. Reputación, contactos y contenido firmado
  siguen valiendo.

### B. Sucesión con temporizador (dead man's switch)

Lo mismo que A, pero sin que nadie tenga que decidir nada: *«si no aparece un acta con
`seq` mayor durante D días, S puede promoverse»*.

Resuelve el caso feo de verdad —que quien desaparezca sea el dueño— pero necesita que
alguien atestigüe la ausencia, y eso es literalmente el **oráculo de frescura** (§2.4.2).
No es una pieza nueva: es la misma que ya hacía falta.

### C. Umbral M-de-N

El acta vale con M firmas de N selladores. Es lo que hace una CA seria y es la única que
quita el punto único de verdad.

Y es cara: hay que reescribir §2.4 entera, porque en cuanto dos coaliciones distintas
pueden sellar el mismo `seq` vuelve el problema del consenso que D4 evitaba. **Para una
persona es sobreingeniería.** Tiene sentido el día que un cliente de Enterprise lo pida
por escrito y lo pague; antes, no.

## 5. Lo que esto obliga a construir, y ya iba siendo hora

**El oráculo de frescura (§2.4.2) aparece por tercera vez.** Está diferido desde 2026-07-25
con el argumento de que *«restaurar un respaldo viejo del vault es poco frecuente»*, y a
estas alturas hacen falta tres cosas distintas que dependen de él:

1. **Réplicas** (`replicas.md` §6.1): con réplicas, una copia atrasada deja de ser un
   accidente raro y pasa a ser el estado normal.
2. **Sucesión con temporizador** (§B de aquí): alguien tiene que poder decir «llevo D días
   sin ver un acta nueva».
3. **Migrar una cuenta al KMS** (`llaves-de-hardware.md`): tras pasar el sellado a la
   llave nueva, la vieja sigue existiendo en cualquier copia del disco anterior. Lo único
   que impide que resucite ante quien no vio el traspaso es el pin de `maxSeq`, y el
   oráculo es lo que cierra esa ventana.

Tres caminos independientes desembocan en la misma pieza aplazada. Eso ya no es una
coincidencia: es la señal de que toca construirla.

## 6. Un detalle que se cuela: el sucesor también tiene que NACER con el KMS

Si el sentido de todo esto es tener raíz de hardware, la bóveda sucesora **se crea con
`profile add --kms`**, no se migra después. Una sucesora cuya maestra se escribió alguna
vez bajo la clave de la máquina hereda el mismo agujero que se estaba tapando, y encima
lo hereda en silencio.

## 7. Orden propuesto

1. **`caps +aprueba` a una segunda bóveda.** Ya funciona; es una decisión, no una tarea.
2. **Oráculo de frescura** (§2.4.2). Es el cuello de botella de todo lo demás.
3. **Sucesor designado a mano** (§A): campo en el acta, comprobación, y el aviso en la
   consola de qué se pierde si la principal vuelve con una rama muerta.
4. **Réplicas de solo lectura** (`replicas.md`), que ya se apoyan en 2 y 3.
5. **Temporizador** (§B), si después de tener 3 sigue haciendo falta.
6. **Umbral** (§C), solo si alguien lo paga.

## 8. Estado

Implementado: **nada de §4**. Lo de §2 (aprobar desde varias bóvedas) funciona hoy y no
hacía falta escribirlo, solo darse cuenta.
