/**
 * Primitivas de ancho/recorte de la TUI (`src/tui/term.js`). Puras, sin terminal.
 * Estas son las que evitan que las líneas coloreadas se desborden y rompan el
 * layout, así que conviene fijarlas.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { stripAnsi, widthOf, trunc, padEnd } from '../src/tui/term.js'

const RED = '\x1b[31m'
const RESET = '\x1b[0m'

test('stripAnsi quita los escapes', () => {
  assert.equal(stripAnsi(`${RED}hola${RESET}`), 'hola')
})

test('widthOf ignora escapes y cuenta emoji/CJK como 2', () => {
  assert.equal(widthOf('abc'), 3)
  assert.equal(widthOf(`${RED}abc${RESET}`), 3)
  assert.equal(widthOf('🔒'), 2)
  assert.equal(widthOf('世界'), 4)
})

test('trunc respeta ancho visible y cierra color', () => {
  assert.equal(trunc('abcdef', 3), 'abc')
  assert.equal(trunc('abc', 10), 'abc')
  assert.equal(trunc('', 5), '')
  assert.equal(trunc('abc', 0), '')
  // no parte un escape por la mitad y añade reset si truncó dentro de color
  const out = trunc(`${RED}abcdef${RESET}`, 3)
  assert.ok(out.startsWith(RED))
  assert.equal(stripAnsi(out), 'abc')
  assert.ok(out.endsWith('\x1b[0m'))
})

test('trunc no corta un emoji ancho a la mitad', () => {
  // 🔒 mide 2; con ancho 1 no cabe → cadena vacía (o solo lo previo)
  assert.equal(stripAnsi(trunc('🔒', 1)), '')
  assert.equal(stripAnsi(trunc('a🔒', 2)), 'a')
})

test('padEnd rellena al ancho visible', () => {
  assert.equal(padEnd('ab', 5), 'ab   ')
  assert.equal(widthOf(padEnd(`${RED}ab${RESET}`, 5)), 5)
  // si ya excede, recorta
  assert.equal(widthOf(padEnd('abcdef', 3)), 3)
})
