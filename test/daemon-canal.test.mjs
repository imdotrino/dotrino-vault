/**
 * El canal CLI↔daemon y el candado de instancia única.
 *
 * Las dos cosas se rompían de forma silenciosa:
 *
 *  · **Sin señales.** El CLI avisaba al daemon con SIGUSR1/SIGUSR2, que **no existen en
 *    Windows**: allí `pair`, `approve`, `members` y la TUI no podían pedirle nada. El
 *    `status` engañaba, porque solo lee un archivo. Ahora el daemon vigila la carpeta, así
 *    que basta con escribir la petición — que es exactamente lo que prueba este test.
 *
 *  · **Dos bóvedas sobre los mismos datos.** El dir NO depende de la carpeta desde la que
 *    lances el comando, así que lanzarlo dos veces daba dos daemons con la misma identidad,
 *    los dos conectados al proxy, y el segundo pisando el pid de `state.json`.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { spawn } from 'node:child_process'
import { fileURLToPath } from 'node:url'

const RAIZ = path.dirname(path.dirname(fileURLToPath(import.meta.url)))
const DAEMON = path.join(RAIZ, 'bin', 'dotrino-vaultd.js')
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'vaultd-'))
const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

function arrancar (dir) {
  const p = spawn(process.execPath, [DAEMON], {
    env: { ...process.env, DOTRINO_VAULT_DIR: dir },
    stdio: ['ignore', 'pipe', 'pipe']
  })
  let salida = ''
  p.stdout.on('data', (d) => { salida += d })
  p.stderr.on('data', (d) => { salida += d })
  return { p, log: () => salida }
}

/** Espera a que exista un archivo, hasta `ms`. Devuelve si apareció. */
async function esperarArchivo (file, ms = 12000) {
  const hasta = Date.now() + ms
  while (Date.now() < hasta) {
    if (fs.existsSync(file)) return true
    await sleep(200)
  }
  return false
}

test('el daemon atiende una petición SIN que nadie le mande una señal (el caso Windows)', async () => {
  const dir = tmp()
  const { p } = arrancar(dir)
  assert.ok(await esperarArchivo(path.join(dir, 'state.json')), 'arrancó')

  // Esto es lo único que hace el CLI en Windows: dejar el archivo. Sin SIGUSR1.
  fs.writeFileSync(path.join(dir, 'pair-request.json'), JSON.stringify({ at: Date.now() }))

  const atendido = await esperarArchivo(path.join(dir, 'pair.json'))
  p.kill()
  assert.ok(atendido, 'el daemon leyó la petición solo con verla aparecer')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('una segunda bóveda sobre los MISMOS datos no arranca', async () => {
  const dir = tmp()
  const primera = arrancar(dir)
  assert.ok(await esperarArchivo(path.join(dir, 'state.json')), 'la primera arrancó')

  const segunda = arrancar(dir)
  const code = await new Promise((r) => segunda.p.on('exit', r))
  primera.p.kill()

  assert.equal(code, 3, 'sale con error, no se pone a competir')
  assert.match(segunda.log(), /Ya hay una bóveda corriendo/i)
  assert.match(segunda.log(), /DOTRINO_VAULT_DIR/, 'y dice cómo tener dos a propósito')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('un pid MUERTO en state.json no bloquea (se cortó la luz)', async () => {
  const dir = tmp()
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({ v: 2, pid: 999999 }))
  const { p } = arrancar(dir)
  const ok = await esperarArchivo(path.join(dir, 'pair.json'), 1) || await esperarArchivo(path.join(dir, 'profiles-list.json'), 12000)
  p.kill()
  assert.ok(ok, 'arrancó igual: el candado era de un proceso que ya no existe')
  fs.rmSync(dir, { recursive: true, force: true })
})
