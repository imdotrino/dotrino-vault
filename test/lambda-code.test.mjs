/**
 * EL CÓDIGO FRESCO DE LA LAMBDA (`lambda/code.mjs` y `lambda/update.mjs`, 2026-10-25).
 *
 * La función corre lo que apunta `code/current.json` de su bucket si es más nuevo que ella, y
 * la bóveda en marcha es quien lo apunta, solo después de verificar el zip. Lo que se prueba:
 * que lo apuntado se ejecuta y lo que no cuadra NO (ni en silencio la versión vieja), y que la
 * actualización sigue las reglas del binario (§15).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { createHash } from 'node:crypto'
import { freshHandler, unzip, writeCurrent, readCurrent } from '../lambda/code.mjs'
import { updateCode, announceIfNew, CHECKED } from '../lambda/update.mjs'
import { memoryStore } from '../lambda/mirror.mjs'
import { isNewer } from '@dotrino/update'
import { readSettings, writeSettings } from '../src/settings.js'
import { readAsked, writeAsked, clearAsked, shouldAsk, firstYes } from '../src/updateApproval.js'

const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p))
const sha = (b) => createHash('sha256').update(b).digest('hex')

/** Un zip de verdad, armado con `zip` como lo arma `build.sh`, con un handler que dice su versión. */
function codeZip (version) {
  const src = tmp('lambda-code-src-')
  fs.mkdirSync(path.join(src, 'lambda'))
  fs.writeFileSync(path.join(src, 'lambda', 'handler.mjs'), `export const handler = async () => ({ ran: ${JSON.stringify(version)} })\n`)
  // Algo que se comprima (deflate) y algo que no (guardado).
  fs.writeFileSync(path.join(src, 'big.txt'), 'dotrino '.repeat(5000))
  fs.writeFileSync(path.join(src, 'tiny'), 'x')
  const out = path.join(tmp('lambda-code-zip-'), 'code.zip')
  execFileSync('zip', ['-qrX', out, '.'], { cwd: src })
  return fs.readFileSync(out)
}

test('unzip deja los archivos tal cual, comprimidos o no', () => {
  const dest = tmp('lambda-unzip-')
  unzip(codeZip('1.0.0'), dest)
  assert.equal(fs.readFileSync(path.join(dest, 'big.txt'), 'utf8'), 'dotrino '.repeat(5000))
  assert.equal(fs.readFileSync(path.join(dest, 'tiny'), 'utf8'), 'x')
  assert.ok(fs.existsSync(path.join(dest, 'lambda', 'handler.mjs')))
})

test('unzip no escribe fuera de su carpeta', () => {
  const out = path.join(tmp('lambda-evil-'), 'evil.zip')
  execFileSync('python3', ['-I', '-c', `import zipfile;z=zipfile.ZipFile(${JSON.stringify(out)},'w');z.writestr('../escape.txt','no');z.close()`])
  assert.throws(() => unzip(fs.readFileSync(out), tmp('lambda-unzip-evil-')), { code: 'code-bad-zip' })
})

test('sin marcador, o con uno que no es más nuevo, corre lo que trajo la pila', async () => {
  const store = memoryStore()
  assert.equal(await freshHandler({ store, myVersion: '2.0.0', isNewer, root: tmp('lambda-root-') }), null)
  await writeCurrent(store, { version: '1.0.0', sha256: 'a'.repeat(64), key: 'x.zip', announced: true })
  assert.equal(await freshHandler({ store, myVersion: '2.0.0', isNewer, root: tmp('lambda-root-') }), null)
  await writeCurrent(store, { version: '2.0.0', sha256: 'a'.repeat(64), key: 'x.zip', announced: true })
  assert.equal(await freshHandler({ store, myVersion: '2.0.0', isNewer, root: tmp('lambda-root-') }), null)
})

test('con uno más nuevo, la invocación la atiende esa versión', async () => {
  const store = memoryStore()
  const zip = codeZip('3.0.0')
  await store.put('code-3.zip', zip)
  await writeCurrent(store, { version: '3.0.0', sha256: sha(zip), key: 'code-3.zip', announced: false })
  const root = tmp('lambda-root-')
  const h = await freshHandler({ store, myVersion: '2.0.0', isNewer, root })
  assert.deepEqual(await h({}, {}), { ran: '3.0.0' })
  // En un contenedor caliente ya está desempaquetada: no se vuelve a bajar.
  store.objects.delete('code-3.zip')
  const again = await freshHandler({ store, myVersion: '2.0.0', isNewer, root })
  assert.deepEqual(await again({}, {}), { ran: '3.0.0' })
})

test('lo apuntado que no cuadra o que no está NO se ejecuta, y tampoco la versión vieja', async () => {
  const store = memoryStore()
  const zip = codeZip('3.0.0')
  await store.put('code-3.zip', zip)
  await writeCurrent(store, { version: '3.0.0', sha256: 'b'.repeat(64), key: 'code-3.zip', announced: false })
  await assert.rejects(freshHandler({ store, myVersion: '2.0.0', isNewer, root: tmp('lambda-root-') }), { code: 'code-mismatch' })
  await writeCurrent(store, { version: '3.0.0', sha256: sha(zip), key: 'otro.zip', announced: false })
  await assert.rejects(freshHandler({ store, myVersion: '2.0.0', isNewer, root: tmp('lambda-root-') }), { code: 'code-missing' })
  await store.put('current.json', Buffer.from('no es json'))
  await assert.rejects(freshHandler({ store, myVersion: '2.0.0', isNewer, root: tmp('lambda-root-') }), { code: 'code-marker-unreadable' })
})

/** Las dependencias de `updateCode`, con la release y la verificación de mentira. */
function deps ({ latest = '3.0.0', verified = true, assets = null } = {}) {
  const zip = codeZip(latest)
  const file = path.join(tmp('lambda-dl-'), 'z.zip')
  fs.writeFileSync(file, zip)
  return {
    zip,
    deps: {
      latestRelease: async () => ({ ok: true, version: latest, assets: assets || [{ name: `dotrino-vault-lambda-${latest}.zip`, url: 'https://x' }] }),
      isNewer,
      fetchVerified: async () => verified ? { ok: true, file } : { ok: false, reason: 'the signature does not check out' },
      readSettings, readAsked, writeAsked, clearAsked, shouldAsk, firstYes,
      checkEveryMs: 24 * 3600_000, repo: 'imdotrino/dotrino-vault'
    }
  }
}

test('hay versión nueva: la verifica, la deja en su bucket y la apunta', async () => {
  const store = memoryStore()
  const { zip, deps: d } = deps()
  const r = await updateCode({ store, dir: tmp('lambda-prof-'), myVersion: '2.0.0', deadline: Date.now() + 60_000, deps: d })
  assert.equal(r.did, 'installed')
  const cur = await readCurrent(store)
  assert.equal(cur.version, '3.0.0')
  assert.equal(cur.sha256, sha(zip))
  assert.equal(cur.from, '2.0.0')
  assert.equal(cur.announced, false)
  // Y la función, al arrancar, la corre.
  const h = await freshHandler({ store, myVersion: '2.0.0', isNewer, root: tmp('lambda-root-') })
  assert.deepEqual(await h({}, {}), { ran: '3.0.0' })
  // Mirar es una vez al día.
  assert.equal((await updateCode({ store, dir: tmp('lambda-prof-'), myVersion: '2.0.0', deadline: Date.now(), deps: d })).did, 'recently-checked')
})

test('lo que no se verifica no se apunta', async () => {
  const store = memoryStore()
  const r = await updateCode({ store, dir: tmp('lambda-prof-'), myVersion: '2.0.0', deadline: Date.now(), deps: deps({ verified: false }).deps })
  assert.equal(r.did, 'not-verified')
  assert.equal(await readCurrent(store), null)
  // Y no cuenta como mirado: la sesión siguiente lo vuelve a intentar.
  await assert.rejects(store.get(CHECKED), { code: 'ENOENT' })
})

test('al día, y «no se pudo mirar» no es «al día»', async () => {
  const store = memoryStore()
  assert.equal((await updateCode({ store, dir: tmp('lambda-prof-'), myVersion: '3.0.0', deadline: Date.now(), deps: deps().deps })).did, 'up-to-date')
  const d = deps().deps
  d.latestRelease = async () => ({ ok: false, reason: 'HTTP 403' })
  const store2 = memoryStore()
  const r = await updateCode({ store: store2, dir: tmp('lambda-prof-'), myVersion: '2.0.0', deadline: Date.now(), deps: d })
  assert.equal(r.did, 'check-failed')
  // Y no se apunta como mirado: la sesión siguiente vuelve a intentarlo.
  await assert.rejects(store2.get(CHECKED), { code: 'ENOENT' })
})

test('con la aprobación encendida se pide una vez; sin un sí no se instala', async () => {
  const store = memoryStore()
  const dir = tmp('lambda-prof-')
  writeSettings(dir, { updateApproval: true })
  let asked = 0
  const vault = {
    approvers: async () => [{ id: 'AB12-CD34', label: 'tel' }],
    askUpdateApproval: () => { asked++; return { answer: Promise.resolve(false), withdraw: () => {} } }
  }
  const r = await updateCode({ store, dir, myVersion: '2.0.0', vault, deadline: Date.now() + 60_000, deps: deps().deps })
  assert.equal(r.did, 'not-approved')
  assert.equal(asked, 1)
  assert.equal(readAsked(dir).result, 'denied')
  assert.equal(await readCurrent(store), null)
  // La misma versión no se vuelve a pedir.
  await store.remove(CHECKED)
  assert.equal((await updateCode({ store, dir, myVersion: '2.0.0', vault, deadline: Date.now() + 60_000, deps: deps().deps })).did, 'not-approved')
  assert.equal(asked, 1)
})

test('con la aprobación encendida y un sí, se instala; sin aprobadores, también', async () => {
  const dir = tmp('lambda-prof-')
  writeSettings(dir, { updateApproval: true })
  const yes = { approvers: async () => [{ id: 'AB12-CD34' }], askUpdateApproval: () => ({ answer: Promise.resolve(true), withdraw: () => {} }) }
  assert.equal((await updateCode({ store: memoryStore(), dir, myVersion: '2.0.0', vault: yes, deadline: Date.now() + 60_000, deps: deps().deps })).did, 'installed')
  const nobody = { approvers: async () => [], askUpdateApproval: () => { throw new Error('no se pide a nadie') } }
  assert.equal((await updateCode({ store: memoryStore(), dir: tmp('lambda-prof-'), myVersion: '2.0.0', vault: nobody, deadline: Date.now(), deps: deps().deps })).did, 'installed')
})

test('un ajuste que no se puede leer no es «el valor por defecto»', async () => {
  const dir = tmp('lambda-prof-')
  fs.writeFileSync(path.join(dir, 'settings.json'), 'roto')
  const r = await updateCode({ store: memoryStore(), dir, myVersion: '2.0.0', deadline: Date.now(), deps: deps().deps })
  assert.equal(r.did, 'settings-unreadable')
})

test('la versión nueva, al arrancar, lo cuenta una vez', async () => {
  const store = memoryStore()
  await writeCurrent(store, { version: '3.0.0', sha256: 'a'.repeat(64), key: 'x.zip', from: '2.0.0', announced: false })
  const told = []
  const vault = { announceUpdate: async (n) => { told.push(n) } }
  assert.equal((await announceIfNew({ store, myVersion: '3.0.0', vault })).did, 'told')
  assert.deepEqual(told, [{ version: '3.0.0', from: '2.0.0' }])
  assert.equal((await announceIfNew({ store, myVersion: '3.0.0', vault })).did, 'nothing')
  // La vieja no dice que corre la nueva.
  await writeCurrent(store, { version: '4.0.0', sha256: 'a'.repeat(64), key: 'y.zip', from: '3.0.0', announced: false })
  assert.equal((await announceIfNew({ store, myVersion: '3.0.0', vault })).did, 'nothing')
})
