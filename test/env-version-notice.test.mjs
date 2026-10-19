/**
 * `dotrino-env` AVISA DE QUE HAY VERSIÓN NUEVA, y no estorba al hacerlo (CONVENCIONES §15).
 *
 * Sin red: se siembra la caché que el aviso lee (`~/.cache/dotrino/update/`), con la fecha
 * de ahora, así que no pregunta a nadie y contesta lo sembrado. Es exactamente el camino de
 * cada invocación menos la primera del día.
 *
 * Lo que se fija es lo que costaría caro romper: que el aviso vaya por STDERR —stdout es de
 * quien canaliza la salida— y que se pueda apagar.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const ROOT = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const CLI = path.join(ROOT, 'lib', 'bin', 'dotrino-env.js')

/** Una caché que dice que hay `latest` publicada, comprobado ahora mismo. */
function cacheCon (latest) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'env-aviso-'))
  fs.mkdirSync(path.join(dir, 'dotrino', 'update'), { recursive: true })
  fs.writeFileSync(path.join(dir, 'dotrino', 'update', '@dotrino_env.json'),
    JSON.stringify({ version: latest, checkedAt: Date.now() }))
  return dir
}

const correr = (env) => spawnSync(process.execPath, [CLI, 'help'], {
  env: { ...process.env, ...env }, encoding: 'utf8', timeout: 20000
})

test('hay una más nueva: lo dice por STDERR, y stdout queda intacto', () => {
  const r = correr({ XDG_CACHE_HOME: cacheCon('999.0.0') })
  assert.match(r.stderr, /hay dotrino-env 999\.0\.0 publicada/)
  assert.match(r.stderr, /npm i -g @dotrino\/env/, 'y dice cómo')
  assert.doesNotMatch(r.stdout, /999\.0\.0/,
    'el aviso se coló en stdout: eso le rompe la tubería a quien canaliza `dotrino-env run`')
})

test('al día, calla', () => {
  const r = correr({ XDG_CACHE_HOME: cacheCon('0.0.1') })
  assert.doesNotMatch(r.stderr + r.stdout, /publicada/)
})

test('se puede apagar, porque en un script estorba', () => {
  const r = correr({ XDG_CACHE_HOME: cacheCon('999.0.0'), DOTRINO_NO_UPDATE_NOTICE: '1' })
  assert.doesNotMatch(r.stderr + r.stdout, /publicada/)
})

test('lo dice UNA vez, no una por cada camino de salida', () => {
  const r = correr({ XDG_CACHE_HOME: cacheCon('999.0.0') })
  assert.equal((r.stderr.match(/hay dotrino-env/g) || []).length, 1)
})
