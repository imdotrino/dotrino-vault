/**
 * El lector de `.env` compartido (`lib/src/envtext.js`), que es por donde entra la
 * configuración de un servicio desde los tres sitios (CLI, TUI y consola remota).
 *
 * Lo que se prueba es la promesa: que se pueda pegar el archivo que la gente YA tiene,
 * y que lo dudoso se rechace ENTERO en vez de cargarse a medias — media configuración
 * aplicada es peor que ninguna, porque el servicio arranca con ella.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { parseEnvText, parseEnvInput } from '../lib/src/envtext.js'

test('lee un .env de los de siempre: comentarios, export y comillas', () => {
  const { items, errors } = parseEnvText(`
# la configuración del proxy
TURN_KEY_ID=k-123
export DB_URL="postgres://uno dos"
  API_TOKEN = 'con espacios alrededor'
`)
  assert.deepEqual(errors, [])
  assert.deepEqual(items, [
    { op: 'set', key: 'TURN_KEY_ID', value: 'k-123' },
    { op: 'set', key: 'DB_URL', value: 'postgres://uno dos' },
    { op: 'set', key: 'API_TOKEN', value: 'con espacios alrededor' }
  ])
})

test('un # a mitad de línea NO corta el valor: una contraseña puede llevarlo', () => {
  const { items } = parseEnvText('DB_PASSWORD=abc#123')
  assert.deepEqual(items, [{ op: 'set', key: 'DB_PASSWORD', value: 'abc#123' }])
})

test('lo dudoso se señala con su línea, y no se inventa un valor', () => {
  const { errors } = parseEnvText([
    'BIEN=1',
    'esto no es una variable',
    'minusculas=2',
    'SIN_VALOR=',
    'BIEN=3'
  ].join('\n'))
  assert.deepEqual(errors, [
    { code: 'shape', line: 2 },
    { code: 'key', line: 3, key: 'minusculas' },
    { code: 'novalue', line: 4, key: 'SIN_VALOR' },
    // Repetida es error, no «gana la última»: adivinar cuál quería el dueño no es
    // asunto de un lector de configuración.
    { code: 'dup', line: 5, key: 'BIEN', first: 1 }
  ])
})

test('un texto sin ninguna variable lo dice, en vez de cargar nada en silencio', () => {
  assert.deepEqual(parseEnvText('\n# solo comentarios\n').errors, [{ code: 'empty' }])
  assert.deepEqual(parseEnvText('').errors, [{ code: 'empty' }])
})

test('en UNA línea también (lo que se puede teclear en la TUI), con comillas', () => {
  const { items, errors } = parseEnvInput('A_UNO=1 A_DOS="dos con espacios" A_TRES=3')
  assert.deepEqual(errors, [])
  assert.deepEqual(items.map((i) => [i.key, i.value]), [
    ['A_UNO', '1'], ['A_DOS', 'dos con espacios'], ['A_TRES', '3']
  ])
})
