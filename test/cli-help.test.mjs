/**
 * `--help` EN CUALQUIER COMANDO ENSEÑA LA AYUDA Y NO HACE NADA.
 *
 * Ningún subcomando lo miraba y se ejecutaban igual: `pair --help` lanzaba una invitación
 * real y `update --help` instaló la versión nueva en la bóveda del dueño (2026-10-05).
 * Se corre la CLI de verdad, contra una carpeta vacía y sin daemon: si algún comando
 * llegara a ejecutarse, fallaría por falta de daemon o saldría a la red, y no daría la ayuda.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawnSync } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const cli = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', 'bin', 'dotrino-vault.js')
const vacia = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-help-'))

for (const cmd of [['update'], ['pair'], ['profile', 'key', 'add'], ['profile', 'password', 'rm'], ['unlock'], ['replica', 'enroll'], ['logins', 'add'], ['update', '-h']]) {
  test(`${cmd.join(' ')} ${cmd.includes('-h') ? '' : '--help'} enseña la ayuda sin hacer nada`, () => {
    const args = cmd.includes('-h') ? cmd : [...cmd, '--help']
    const r = spawnSync(process.execPath, [cli, ...args], {
      env: { ...process.env, DOTRINO_VAULT_DIR: vacia, DOTRINO_LANG: 'es' },
      encoding: 'utf8',
      timeout: 15_000
    })
    assert.equal(r.status, 0, r.stderr)
    assert.match(r.stdout, /^dotrino-vault — /, 'la primera línea es la de la ayuda')
    assert.doesNotMatch(r.stdout + r.stderr, /Mirando qué hay publicado|daemon|no parece haber arrancado/i)
    assert.deepEqual(fs.readdirSync(vacia), [], 'no escribió nada en la carpeta de la bóveda')
  })
}
