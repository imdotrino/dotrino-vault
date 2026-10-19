/**
 * NINGÚN ARCHIVO DE CÓDIGO LLEVA UN BYTE NUL.
 *
 * Suena a manía y no lo es: un NUL literal dentro de un template hace que `file` dé el
 * archivo por binario y que CUALQUIER `grep` sobre él devuelva vacío **en silencio**. O
 * sea que el archivo sigue funcionando y a la vez deja de existir para las herramientas
 * con las que se busca — que es exactamente el fallo que no se nota hasta que te vuelves
 * loco buscando una función que está ahí delante.
 *
 * Ya pasó dos veces en `secretsStore.js` (el separador de una clave de mapa, escrito como
 * byte en vez de como escape). A la segunda, se fija con un test.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'

const RAIZ = path.join(import.meta.dirname, '..')
const DIRS = ['src', 'lib/src', 'bin', 'test', 'web/src']

function * archivos (dir) {
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const p = path.join(dir, e.name)
    if (e.isDirectory()) yield * archivos(p)
    else if (/\.(m?js|ts|vue)$/.test(e.name)) yield p
  }
}

test('ningun archivo de codigo lleva un byte NUL (rompe grep en silencio)', () => {
  const malos = []
  for (const dir of DIRS) {
    const abs = path.join(RAIZ, dir)
    if (!fs.existsSync(abs)) continue
    for (const f of archivos(abs)) {
      if (fs.readFileSync(f).includes(0)) malos.push(path.relative(RAIZ, f))
    }
  }
  assert.deepEqual(malos, [], 'escríbelo como escape (\\u0000), no como byte')
})
