/**
 * NINGÚN PERMISO INVISIBLE, Y NINGUNO SIN NOMBRE.
 *
 * La pantalla de permisos de la TUI dibujaba desde una lista escrita a mano, así que cada
 * permiso nuevo del acta quedaba fuera sin que nadie lo notara: le pasó a `secrets`, a
 * `sealer` y a `unattended`, tres veces el mismo fallo y semanas cada vez. Y un permiso
 * que la pantalla no enseña es un permiso que el dueño cree que no existe.
 *
 * Esto ata las tres listas que tienen que decir lo mismo: la del acta (`DEVICE_CAPS`), el
 * orden de la pantalla, y los dos diccionarios.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { DEVICE_CAPS, CAPS } from '@dotrino/identity/acta'
import { dict, LANGS } from '../src/tui/i18n.js'

test('la pantalla enseña TODOS los permisos de aparato que existen', async () => {
  const src = await import('node:fs').then((fs) => fs.readFileSync(new URL('../src/tui/app.js', import.meta.url), 'utf8'))
  // Se lee el fuente porque `CAPS_ORDER` no se exporta: lo que importa no es la variable,
  // es que la lista curada de la pantalla no se quede corta.
  const m = /const ORDEN = \[([^\]]*)\]/.exec(src)
  assert.ok(m, 'la pantalla tiene que tener su orden curado')
  const orden = m[1].split(',').map((x) => x.trim().replace(/^'|'$/g, '')).filter(Boolean)
  for (const cap of DEVICE_CAPS) {
    assert.ok(orden.includes(cap),
      `«${cap}» no está en el orden de la pantalla: saldría al final, ponlo donde toque`)
  }
})

test('todos los permisos tienen nombre y explicación en los dos idiomas', () => {
  for (const lang of LANGS) {
    const t = dict(lang)
    for (const cap of CAPS) {
      // `secrets` es una función (lleva el cajón dentro); los demás, texto.
      const nombre = t.capName[cap]
      assert.ok(nombre, `falta el nombre de «${cap}» en ${lang}: la fila saldría en blanco`)
      if (cap !== 'secrets') {
        assert.equal(typeof nombre, 'string')
        assert.ok(t.capHint[cap], `falta la explicación de «${cap}» en ${lang}`)
      }
    }
  }
})

/**
 * EL NOMBRE DICE EL ACTO, NO LA CONSECUENCIA (dueño, 2026-09-02).
 *
 * «Sellar el acta» obligaba a saberse el modelo para entender qué concedes. No se puede
 * comprobar el estilo de una frase, pero sí que no reaparezcan las palabras que hicieron
 * falta explicar: son las que el dueño señaló.
 */
test('los nombres de los permisos no usan jerga', () => {
  const jerga = /\bacta\b|\bsellar\b|\bcert|\bscope\b|\bpubkey\b|\brecord\b|\bseal\b/i
  for (const lang of LANGS) {
    const t = dict(lang)
    for (const cap of CAPS) {
      if (cap === 'secrets') continue
      assert.ok(!jerga.test(t.capName[cap]),
        `el nombre de «${cap}» en ${lang} usa jerga: "${t.capName[cap]}"`)
    }
  }
})
