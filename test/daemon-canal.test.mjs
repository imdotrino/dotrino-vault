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
  assert.match(segunda.log(), /vault is already running/i)
  assert.match(segunda.log(), /DOTRINO_VAULT_DIR/, 'y dice cómo tener dos a propósito')
  fs.rmSync(dir, { recursive: true, force: true })
})

/**
 * EL VOLCADO ES UNA RESPUESTA, NO UN LATIDO.
 *
 * El daemon repasa su carpeta cada dos segundos. Mientras volcaba `devices.json`,
 * `acta.json` y `secrets-list.json` en cada vuelta —preguntara alguien o no—, ese repaso
 * caía justo entre la respuesta y quien la esperaba y se la llevaba por delante: la TUI se
 * quedaba en «Cargando dispositivos…» y a los seis segundos decía que el daemon no
 * responde, con el daemon sano y habiendo contestado en milisegundos.
 */
test('nadie pregunta: el daemon NO vuelca devices.json por su cuenta', async () => {
  const dir = tmp()
  const { p } = arrancar(dir)
  assert.ok(await esperarArchivo(path.join(dir, 'state.json')), 'arrancó')

  const dev = path.join(dir, 'devices.json')
  // Que exista uno viejo no cuenta: se borra y se le dan varias vueltas del repaso (2 s).
  fs.rmSync(dev, { force: true })
  await sleep(5000)
  const solo = fs.existsSync(dev)
  p.kill()
  assert.equal(solo, false, 'sin petición no hay volcado')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('y la respuesta a una petición NO se la pisa el repaso siguiente', async () => {
  const dir = tmp()
  const { p } = arrancar(dir)
  assert.ok(await esperarArchivo(path.join(dir, 'state.json')), 'arrancó')

  const dev = path.join(dir, 'devices.json')
  fs.rmSync(dev, { force: true })
  fs.writeFileSync(path.join(dir, 'dump-request.json'), JSON.stringify({ id: 'yo-1', at: Date.now() }))

  const leer = () => { try { return JSON.parse(fs.readFileSync(dev, 'utf8')) } catch { return null } }
  let d = null
  const hasta = Date.now() + 10000
  while (Date.now() < hasta && !(d = leer())?.at) await sleep(100)
  assert.equal(d?.req, 'yo-1', 'el volcado dice a QUIÉN contesta')

  // Lo que rompía: dos vueltas del repaso después, el archivo era otro (`req: null`) y
  // quien esperaba su respuesta ya no la encontraba nunca.
  await sleep(5000)
  p.kill()
  assert.equal(leer()?.req, 'yo-1', 'la respuesta sigue ahí, sin pisar')
  fs.rmSync(dir, { recursive: true, force: true })
})

test('un pid MUERTO en state.json no bloquea (se cortó la luz)', async () => {
  const dir = tmp()
  fs.writeFileSync(path.join(dir, 'state.json'), JSON.stringify({ v: 2, pid: 999999 }))
  const { p } = arrancar(dir)
  // Arrancó = `state.json` pasa a llevar SU pid (el archivo ya estaba, con el muerto).
  // Antes se esperaba a `profiles-list.json`, que el daemon volcaba solo cada dos
  // segundos; ya no lo hace —ese archivo es la RESPUESTA a una petición y volcarlo sin
  // que nadie pregunte se llevaba por delante las respuestas de verdad (ver daemon.js).
  const hasta = Date.now() + 12000
  let ok = false
  while (Date.now() < hasta && !ok) {
    const s = JSON.parse(fs.readFileSync(path.join(dir, 'state.json'), 'utf8') || '{}')
    ok = Number(s.pid) === p.pid
    if (!ok) await sleep(200)
  }
  p.kill()
  assert.ok(ok, 'arrancó igual: el candado era de un proceso que ya no existe')
  fs.rmSync(dir, { recursive: true, force: true })
})
