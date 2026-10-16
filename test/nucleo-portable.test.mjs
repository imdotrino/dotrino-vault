/**
 * EL NÚCLEO DE LA BÓVEDA NO DEPENDE DE NODE.
 *
 * El binario, la pestaña y la extensión corren el MISMO `lib/src/core/vault.js` (regla de
 * las tres versiones, dueño 2026-09-17). Lo que depende de dónde corre llega en la
 * plataforma (`src/platform.js` en el binario, `lib/src/browser.js` en el navegador). Un
 * `node:fs`, un `Buffer` o un `process` metido en el núcleo funciona en el binario y rompe
 * las otras dos sin que ninguna prueba de Node lo note: esta lo para.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const lib = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'lib', 'src')

/** Todo lo que carga el navegador: el núcleo y lo que importa de `lib/src`. */
function archivosDelNavegador () {
  const vistos = new Set()
  const ir = (f) => {
    if (vistos.has(f)) return
    vistos.add(f)
    const code = fs.readFileSync(f, 'utf8')
    for (const m of code.matchAll(/(?:from|import)\s*\(?\s*['"](\.{1,2}\/[^'"]+)['"]/g)) ir(path.join(path.dirname(f), m[1]))
  }
  ir(path.join(lib, 'browser.js'))
  return [...vistos]
}

test('lo que carga la bóveda del navegador no importa nada de Node', () => {
  const malos = []
  for (const f of archivosDelNavegador()) {
    // Fuera los comentarios: explicar por qué no se usa `Buffer` no es usarlo.
    const code = fs.readFileSync(f, 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')
    const rel = path.relative(lib, f)
    if (/from\s*['"]node:|from\s*['"](fs|path|os|crypto|net|child_process)['"]/.test(code)) malos.push(`${rel}: importa un módulo de Node`)
    if (/\bBuffer\./.test(code)) malos.push(`${rel}: usa Buffer`)
    if (/\bprocess\.(env|argv|pid|platform|getuid|cwd|exit)/.test(code)) malos.push(`${rel}: usa process`)
  }
  assert.deepEqual(malos, [], 'el núcleo tiene que correr igual en el navegador')
})
