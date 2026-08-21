# Propuesta: que el SERVICIO diga qué variables necesita

> Idea del dueño, 2026-08-21, mientras se definía la configuración del content node:
> *"un servicio debería poder proponer al vault qué variables necesita, para que en el
> TUI y en la consola sea visible"*. **Es una propuesta: no está diseñada ni
> implementada.** Queda aquí para no perderla.

## El problema, con un ejemplo real

Hoy la bóveda guarda pares `CLAVE=valor` y no sabe nada de ellos. Quien administra tiene
que saber **de memoria o de un README** que el content node quiere `CONTENT_STORAGE`, y
que si vale `s3` entonces hacen falta otras siete, y que dos de ellas son secretas y
cinco no. En la pantalla no hay ninguna pista: hay un cajón vacío.

Eso produce los tres fallos de siempre: variables mal escritas que no dan error sino
silencio, servicios configurados a medias que *parecen* andar, y secretos marcados
públicos por descuido.

## La idea

Que el **agente**, al presentarse, le pase a la bóveda un **manifiesto** de lo que ese
servicio consume. Algo del orden de:

```
{ key: 'CONTENT_STORAGE', required: true,  public: true,
  values: ['local', 's3'], default: 'local',
  desc: { es: 'Qué almacén usa el node', en: 'Which store the node uses' } }
{ key: 'CONTENT_S3_SECRET', required: 'CONTENT_STORAGE=s3', public: false,
  desc: { es: 'Token del bucket privado', en: 'Private bucket token' } }
```

Con eso, el TUI y la consola pueden **enseñar el formulario del servicio** en vez de un
cajón vacío: qué falta, qué es secreto, qué valores admite, y qué está de más.

## Por qué encaja

- **El agente ya habla con la bóveda** por un canal firmado y cifrado; el manifiesto es
  un mensaje más, y llega en el mismo `hello`.
- **No cambia el modelo de secretos:** el manifiesto describe *qué* se guarda, nunca
  *qué vale*. Es metadato de la configuración, así que puede ser público entero.
- Es lo que hace que **`public: false` deje de ser un descuido**: si el servicio dice
  que esa clave es un token, la consola puede negarse a marcarla pública, en vez de
  confiar en que quien administra se acuerde.

## Lo que hay que decidir antes de escribir una línea

1. **Quién manda si no coinciden.** Si el manifiesto dice `required` y la variable no
   está: ¿el servicio se niega a arrancar, o arranca degradado y lo reporta? (Lo segundo
   es lo que hace hoy el content node y funciona bien.)
2. **Confianza.** El manifiesto lo manda el propio servicio, así que es *lo que él dice
   que necesita*, no una autoridad. No debería poder **crear** cajones ni tocar valores;
   solo describir el suyo.
3. **Vigencia.** Un manifiesto viejo de un servicio que ya no corre no debería ensuciar
   la pantalla para siempre: o caduca, o se ve marcado como "no visto desde …".
4. **Idioma.** Las descripciones las lee una persona, así que van bilingües (§9 de las
   convenciones), y eso ya obliga a una forma como la de arriba.
5. **¿Y los servicios que no lo mandan?** Todos, hoy. Tiene que degradar a lo de ahora
   sin ruido: sin manifiesto, la pantalla es la de siempre.

## Relación con lo ya escrito

- `secretos-sellados.md` §8 — cómo se guardan y quién puede verlos. Esta propuesta no
  toca nada de eso.
- `dotrino-content/docs/DISENO.md` §15.14 — el caso que la disparó: una variable pública
  que define la integración y siete que solo existen si vale `s3`.
