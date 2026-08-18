/**
 * El store de secretos v4: dos cajones, la mezcla con el aparato encima, la
 * visibilidad, y —lo nuevo— que **el archivo no contenga ningún valor privado en
 * claro**, que es la propiedad entera de este trabajo.
 *
 * Se prueba con un SELLADOR FALSO, determinista y legible. El store no hace
 * criptografía (recibe el puerto inyectado), así que aquí se comprueba la FORMA y las
 * reglas; que los sobres sean sobres de verdad lo prueba `sealer.test.mjs`.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { openSecretsStore, NeedsPassword } from '../src/secretsStore.js'
import { readJson, writeJson } from '../src/paths.js'
import { atRestFor } from '../src/atrest.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'dotrino-secrets-'))

/** Contraseña de mentira: el sellador falso solo comprueba que sea la misma. */
const PWD = 'llave-de-prueba'

/**
 * Sellador falso: «cifrar» es envolver en un marcador reconocible. Determinista, para
 * que un test pueda afirmar exactamente qué quedó escrito. Lo importante es que
 * respete el contrato: sin la contraseña correcta no se abre nada.
 */
function fakeSealer () {
  let n = 0
  return {
    openMaster (blob, adminKey) {
      if (adminKey !== PWD) throw new Error('wrong password')
      if (!blob) return {}
      return JSON.parse(blob.replace(/^SEALED\(/, '').replace(/\)$/, ''))
    },
    sealMaster (obj, adminKey) {
      if (adminKey !== PWD) throw new Error('wrong password')
      return `SEALED(${JSON.stringify(obj)})`
    },
    cekFor (master, owner) {
      if (!master[owner]) master[owner] = `cek-${owner}-${++n}`
      return master[owner]
    },
    newCek (master, owner) {
      master[owner] = `cek-${owner}-${++n}`
      return master[owner]
    },
    // El «cifrado» tiene que ESCONDER de verdad, aunque sea de mentira: si el falso
    // dejara el texto a la vista, los tests que afirman que el archivo no contiene
    // ningún valor privado pasarían a ser una comprobación de nada.
    encrypt (cek, value) { return { k: cek, ct: Buffer.from(value, 'utf8').toString('base64') } },
    decrypt (master, sobre, owner) {
      const cek = master[owner]
      if (!cek || sobre.k !== cek) throw new Error('cannot open: wrong key')
      return Buffer.from(sobre.ct, 'base64').toString('utf8')
    },
    wrapFor (cek, members) {
      const wraps = {}; const sinLlave = []
      for (const m of members || []) {
        if (!m?.encPub) { sinLlave.push(m?.pub); continue }
        wraps[m.pub] = { epk: m.encPub, ct: `wrap(${cek})` }
      }
      return { wraps, sinLlave }
    }
  }
}

const miembros = (...pubs) => pubs.map((p) => ({ pub: p, encPub: `enc-${p}` }))
const abrir = (dir, sealer) => openSecretsStore(dir, { sealer })

/** El archivo tal cual quedó en el disco (descifrando solo el cifrado en reposo). */
const enDisco = (dir) => readJson(path.join(dir, 'secrets.json'), null, atRestFor(dir))

test('v4: la privada queda SELLADA en el disco y la pública en claro', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer())

  await s.set('proxy', 'TURN_KEY', 'secreto-de-verdad', false, PWD)
  await s.set('proxy', 'PUBLIC_URL', 'wss://proxy.dotrino.com', true, PWD)

  const raw = JSON.stringify(enDisco(dir))
  assert.equal(raw.includes('secreto-de-verdad'), false, 'una privada NO puede aparecer en claro en el archivo')
  assert.equal(raw.includes('wss://proxy.dotrino.com'), true, 'una publica si: para eso se marco')

  // Y con la contraseña se vuelve a leer igual.
  const abierto = await s.openBundle('proxy', null, PWD)
  assert.equal(abierto.TURN_KEY, 'secreto-de-verdad')
  assert.equal(abierto.PUBLIC_URL, 'wss://proxy.dotrino.com')
})

test('sin contraseña: se sirve y se lista, pero no se escribe una privada', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer())
  await s.set('proxy', 'TURN_KEY', 'k', false, PWD)
  await s.set('proxy', 'URL', 'https://x', true, PWD)

  // Servir es lo que tiene que seguir funcionando con el perfil bloqueado.
  const sinSellador = openSecretsStore(dir)
  const b = sinSellador.bundleFor('proxy')
  assert.deepEqual(Object.keys(b.entries).sort(), ['TURN_KEY', 'URL'])
  assert.equal(b.entries.TURN_KEY.pub, false)
  assert.equal(b.entries.URL.v, 'https://x')
  assert.deepEqual(sinSellador.publicOf('proxy'), { URL: 'https://x' }, 'las publicas se leen sin contrasena')
  assert.equal(sinSellador.list().proxy.length, 2, 'los nombres tambien')

  // Escribir una privada, no.
  await assert.rejects(() => sinSellador.set('proxy', 'OTRA', 'x', false), NeedsPassword)
  // Pero una pública sí: no hay nada que sellar.
  await sinSellador.set('proxy', 'OTRA_PUB', 'v', true)
  assert.equal(sinSellador.publicOf('proxy').OTRA_PUB, 'v')
  // Y borrar tampoco pide nada: quitar algo no exige poder leerlo.
  assert.equal(await sinSellador.delete('proxy', 'OTRA_PUB'), true)
})

test('la mezcla no cambia: el cajon del APARATO pisa al del scope', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer())
  await s.set('proxy', 'PUERTO', '8080', true, PWD)
  await s.set('proxy', 'TURN_KEY', 'del-scope', false, PWD)
  await s.setDevice('pub-A', 'PUERTO', '9090', true, PWD)

  const b = s.bundleFor('proxy', 'pub-A')
  assert.equal(b.entries.PUERTO.v, '9090', 'manda el aparato')
  assert.equal(b.entries.TURN_KEY.pub, false, 'y lo del scope sigue llegando')

  // Otro aparato no ve lo del primero.
  assert.equal(s.bundleFor('proxy', 'pub-B').entries.PUERTO.v, '8080')
})

test('el bundle lleva SOLO la envoltura de quien pregunta', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer())
  await s.set('proxy', 'K', 'v', false, PWD)
  await s.rewrap('ns:proxy', miembros('pub-A', 'pub-B'), PWD)

  const a = s.bundleFor('proxy', 'pub-A')
  assert.ok(a.ns.wrap, 'A recibe la suya')
  assert.equal(a.ns.wrap.epk, 'enc-pub-A')
  // Las de sus companeros no salen de la maquina: son llaves de otros.
  assert.equal(JSON.stringify(a).includes('enc-pub-B'), false)
})

test('rewrap avisa de los miembros SIN llave de cifrado en vez de fallar callado', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer())
  await s.set('proxy', 'K', 'v', false, PWD)

  const r = await s.rewrap('ns:proxy', [
    { pub: 'pub-A', encPub: 'enc-pub-A' },
    { pub: 'pub-viejo', encPub: null }
  ], PWD)
  assert.equal(r.wrapped, 1)
  assert.deepEqual(r.sinLlave, ['pub-viejo'], 'hay que poder DECIRLO: si no, arranca sin config y nadie sabe por que')
})

test('rotate: clave nueva, valores recifrados, y el que salio ya no abre', async () => {
  const dir = tmp()
  const sealer = fakeSealer()
  const s = abrir(dir, sealer)
  await s.set('proxy', 'TURN_KEY', 'secreto', false, PWD)
  await s.rewrap('ns:proxy', miembros('pub-A', 'pub-B'), PWD)

  const cekVieja = sealer.openMaster(enDisco(dir).master, PWD)['ns:proxy']
  const r = await s.rotate('ns:proxy', miembros('pub-A'), PWD)

  assert.equal(r.rotated, 1, 'se recifra la privada')
  assert.equal(r.gen, 2, 'nueva generacion')
  const master = sealer.openMaster(enDisco(dir).master, PWD)
  assert.notEqual(master['ns:proxy'], cekVieja, 'la CEK cambia de verdad')
  assert.equal(await s.openBundle('proxy', null, PWD).then((o) => o.TURN_KEY), 'secreto', 'y el valor sigue ahi')

  // El expulsado ya no tiene envoltura.
  assert.equal(s.bundleFor('proxy', 'pub-B').ns, null)
  assert.ok(s.bundleFor('proxy', 'pub-A').ns.wrap)
})

test('visibilidad: privada -> publica descifra, y al reves vuelve a sellar', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer())
  await s.set('proxy', 'K', 'valor', false, PWD)

  assert.equal(await s.setVisibility('proxy', 'K', true, PWD), true)
  assert.equal(s.publicOf('proxy').K, 'valor')
  assert.equal(JSON.stringify(enDisco(dir)).includes('valor'), true, 'ahora si esta en claro, porque es publica')

  assert.equal(await s.setVisibility('proxy', 'K', false, PWD), true)
  assert.deepEqual(s.publicOf('proxy'), {}, 'ya no se ensena')
  assert.equal(JSON.stringify(enDisco(dir)).includes('valor'), false, 'y vuelve a estar sellada')
})

test('migracion v3 -> v4: sella todo, deja respaldo, y no cambia ningun valor', async () => {
  const dir = tmp()
  // Un archivo v3 tal cual lo escribía la versión anterior.
  writeJson(path.join(dir, 'secrets.json'), {
    schemaVersion: 3,
    ns: { proxy: { TURN_KEY: { v: 'secreto-v3', pub: false }, URL: { v: 'https://x', pub: true } } },
    dev: { 'pub-A': { PROXY_PEERS: { v: 'wss://otro', pub: false } } }
  }, atRestFor(dir))

  const s = abrir(dir, fakeSealer())
  assert.equal(s.isLegacy(), true, 'al abrir NO migra: sellar exige contrasena y arrancar no debe pedirla')
  // Y mientras tanto sigue sirviendo, que es lo que permite deshacer el despliegue.
  assert.equal(s.bundleFor('proxy', 'pub-A').entries.TURN_KEY.v, 'secreto-v3')

  const r = await s.migrate((owner) => (owner === 'ns:proxy' ? miembros('pub-A') : miembros('pub-A')), PWD)
  assert.equal(r.migrated, true)
  assert.equal(s.isLegacy(), false)

  const raw = JSON.stringify(enDisco(dir))
  assert.equal(raw.includes('secreto-v3'), false, 'la privada del scope queda sellada')
  assert.equal(raw.includes('wss://otro'), false, 'y la del aparato tambien')
  assert.equal(raw.includes('https://x'), true, 'la publica se queda en claro')

  const abierto = await s.openBundle('proxy', 'pub-A', PWD)
  assert.equal(abierto.TURN_KEY, 'secreto-v3')
  assert.equal(abierto.PROXY_PEERS, 'wss://otro')
  assert.equal(abierto.URL, 'https://x')

  assert.equal(fs.existsSync(path.join(dir, 'secrets.json.v3.bak')), true, 'deshacer tiene que ser un mv')
})

test('migracion: si la comprobacion falla, NO se toca nada', async () => {
  const dir = tmp()
  writeJson(path.join(dir, 'secrets.json'), {
    schemaVersion: 3,
    ns: { proxy: { K: { v: 'original', pub: false } } },
    dev: {}
  }, atRestFor(dir))

  // Sellador roto: descifra devolviendo otra cosa. Es el fallo que la verificación
  // antes-de-reemplazar existe para atrapar.
  const roto = fakeSealer()
  roto.decrypt = () => 'OTRA-COSA'

  const s = abrir(dir, roto)
  await assert.rejects(() => s.migrate(() => miembros('pub-A'), PWD), /migration check failed/)
  assert.equal(s.isLegacy(), true, 'sigue en v3')
  assert.equal(enDisco(dir).ns.proxy.K.v, 'original', 'y el valor original intacto')
})

test('forgetDevice borra el cajon entero del aparato', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer())
  await s.setDevice('pub-A', 'K', 'v', false, PWD)
  await s.setDevice('pub-B', 'K', 'v', false, PWD)

  assert.equal(s.forgetDevice('pub-A'), 1)
  assert.deepEqual(s.listDevices()['pub-A'], undefined)
  assert.equal(s.listDevices()['pub-B'].length, 1, 'no toca al de al lado')
})

test('batch: muchas escrituras, un guardado (y ahora acepta async)', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer())
  await s.batch(async () => {
    for (const k of ['A', 'B', 'C']) await s.set('proxy', k, 'v-' + k, false, PWD)
    // A media carga, el disco todavía no tiene nada: ese es el sentido del grupo.
    assert.equal(enDisco(dir).ns.proxy, undefined)
  })
  assert.equal(Object.keys(enDisco(dir).ns.proxy.vars).length, 3)
})

test('las claves y los valores se siguen validando', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer())
  await assert.rejects(() => s.set('proxy', 'minusculas', 'v', false, PWD), /invalid key/)
  await assert.rejects(() => s.set('proxy', 'K', '', false, PWD), /non-empty/)
  await assert.rejects(() => s.set('MAYUS', 'K', 'v', false, PWD), /invalid namespace/)
})
