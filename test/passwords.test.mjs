/**
 * La bóveda de CONTRASEÑAS atendida por el vault.
 *
 * Lo que se prueba aquí no es el protocolo (eso es de `@dotrino/passmanager`, que trae
 * sus propios tests), sino que el vault le pone lo que en `passmanager serve` había que
 * improvisar: el acta decide quién pide, la aprobación es la del teléfono, y la
 * bitácora es la misma que audita firmas y enrolamientos.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createPasswordDesk } from '../src/passwords.js'
import { makeVaultKey } from '@dotrino/passmanager'
import { RemoteVault, ProxyTransport, makeEncKeypair, seal, open, isSealed, CODES } from '@dotrino/passmanager'

/** Red de mentira que imita al cliente de verdad: sella al enviar, abre al entregar. */
function red () {
  const nodos = new Map()
  function cliente (pubkey) {
    const handlers = []
    const c = {
      pubkey,
      encPrivate: null,
      on (ev, fn) { if (ev === 'message') handlers.push(fn) },
      off (ev, fn) { const i = handlers.indexOf(fn); if (i >= 0) handlers.splice(i, 1) },
      async sendSealed (dests, payload, { peerEncPub } = {}) {
        if (!peerEncPub) throw Object.assign(new Error('sin llave'), { code: CODES.UNSEALED })
        c.sendByPubkey(dests, await seal(payload, peerEncPub))
      },
      sendByPubkey (dests, payload) {
        for (const d of [].concat(dests)) {
          const destino = nodos.get(d)
          if (destino) setTimeout(() => destino._deliver(pubkey, payload), 0)
        }
      },
      async _deliver (from, payload) {
        if (isSealed(payload)) {
          if (!c.encPrivate) return
          let abierto
          try { abierto = await open(payload, c.encPrivate) } catch { return }
          for (const h of handlers) h(from, abierto, { fromPubkey: from, sealed: true })
          return
        }
        for (const h of handlers) h(from, payload, { fromPubkey: from, sealed: false })
      },
    }
    nodos.set(pubkey, c)
    return c
  }
  return { cliente }
}

function memStore () {
  const m = new Map()
  return { async get (k) { return m.get(k) }, async set (k, v) { m.set(k, v) } }
}

async function montar (extra = {}) {
  const net = red()
  const boveda = net.cliente('VAULT')
  const aparato = net.cliente('APARATO')

  const encVault = await makeEncKeypair()
  const encAparato = await makeEncKeypair()
  boveda.encPrivate = encVault.privateKey
  aparato.encPrivate = encAparato.privateKey

  const bitacora = []
  const avisos = []

  const desk = createPasswordDesk({
    client: boveda,
    store: memStore(),
    cek: await makeVaultKey(),
    // El ACTA es quien decide, no este módulo.
    isAllowed: (pub) => pub === 'APARATO',
    encPubOf: (pub) => (pub === 'APARATO' ? encAparato.encPub : null),
    audit: (op, info) => bitacora.push({ op, ...info }),
    approve: async (r) => { avisos.push(r.pubkey); return true },
    ...extra,
  }).start()

  await desk.vault.put({ title: 'Salesforce', sites: ['salesforce.com'], username: 'sandrade@dotrino.com', secret: 'hunter2' })

  const remota = new RemoteVault(new ProxyTransport({
    client: aparato, peerPubkey: 'VAULT', peerEncPub: encVault.encPub, timeoutMs: 600,
  }))
  return { desk, remota, bitacora, avisos, net }
}

test('vault-passwords: un aparato del acta pide de a una', async () => {
  const { remota } = await montar({ needsApproval: () => false })
  const hits = await remota.find('https://login.salesforce.com/')
  assert.equal(hits.length, 1)
  assert.ok(!JSON.stringify(hits).includes('hunter2'), 'el secreto viajó en la lista')
  assert.equal((await remota.get(hits[0].id)).secret, 'hunter2')
})

test('vault-passwords: un aparato que el acta no reconoce no recibe nada', async () => {
  const { remota, bitacora } = await montar({ isAllowed: () => false })
  await assert.rejects(() => remota.find('https://salesforce.com/'), e => e.code === CODES.DENIED)
  assert.equal(bitacora.at(-1).outcome, 'denied')
})

test('vault-passwords: la aprobación es la del vault (el teléfono), una por aparato', async () => {
  const { remota, avisos } = await montar({ needsApproval: () => true })
  const [hit] = await remota.find('https://salesforce.com/')
  await remota.get(hit.id)
  await remota.get(hit.id)
  assert.deepEqual(avisos, ['APARATO'], 'volvió a molestar al teléfono')
})

test('vault-passwords: sin el visto bueno del teléfono, no sale la credencial', async () => {
  const { remota } = await montar({ needsApproval: () => true, approve: async () => false })
  const [hit] = await remota.find('https://salesforce.com/')
  await assert.rejects(() => remota.get(hit.id), e => e.code === CODES.DENIED)
})

test('vault-passwords: la bitácora apunta la operación, NUNCA qué credencial', async () => {
  const { remota, bitacora } = await montar({ needsApproval: () => false })
  const [hit] = await remota.find('https://salesforce.com/')
  await remota.get(hit.id)

  assert.deepEqual(bitacora.map(b => b.op + ':' + b.outcome), ['find:served', 'get:served'])
  const texto = JSON.stringify(bitacora)
  for (const dato of ['hunter2', 'salesforce.com', 'sandrade@dotrino.com', hit.id]) {
    assert.ok(!texto.includes(dato), `la bitácora guardó «${dato}»`)
  }
})

test('vault-passwords: bloquear el perfil cierra también las contraseñas', async () => {
  const { desk, remota } = await montar({ needsApproval: () => false })
  desk.lock()
  await assert.rejects(() => remota.find('https://salesforce.com/'), e => e.code === CODES.LOCKED)
})

test('vault-passwords: ni el vault le deja listar la bóveda a un aparato', async () => {
  const { desk, remota } = await montar({ needsApproval: () => false })

  // Ser el vault no cambia la regla: un aparato no lista.
  await assert.rejects(() => remota.list(), e => e.code === CODES.NO_KEY)

  // Y aquí, del lado de la llave, listar es lo normal — es la misma bóveda.
  const todas = await desk.vault.list()
  assert.equal(todas.length, 1)
  assert.equal(todas[0].title, 'Salesforce')
})

// --- El cableado con el vault ------------------------------------------------
//
// Lo de arriba prueba el módulo; esto prueba las piezas que lo enganchan al vault y que
// NO son suyas: el almacén cifrado en reposo, la llave que nace sola, y la lista de
// aparatos autorizados. Sin esto el módulo existiría sin que nadie lo montara.

import { mkdtemp, rm, readFile } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { atRestFor } from '../src/atrest.js'
import fs from 'node:fs'

/** Reproduce lo que `vault.js` monta alrededor del desk, con las mismas piezas. */
function piezasDelVault (dir) {
  const file = join(dir, 'passwords.json')
  const atRest = atRestFor(dir)
  const leer = () => { try { return JSON.parse(atRest.decrypt(fs.readFileSync(file, 'utf8'))) } catch { return null } }
  const escribir = (d) => fs.writeFileSync(file, atRest.encrypt(JSON.stringify(d)), { mode: 0o600 })

  return {
    file,
    leer,
    store: {
      async get (k) { return leer()?.data?.[k] },
      async set (k, v) {
        const d = leer() || { v: 1, data: {}, devices: [] }
        d.data = { ...(d.data || {}), [k]: v }
        escribir(d)
      },
    },
    devices: () => leer()?.devices || [],
    setDevice (pub, label) {
      const d = leer() || { v: 1, data: {}, devices: [] }
      escribir({ ...d, devices: [...(d.devices || []).filter(x => x.pubkey !== pub), { pubkey: pub, label, ts: 1 }] })
    },
    async key () {
      const d = leer()
      if (d?.cek) {
        return crypto.subtle.importKey('raw', Uint8Array.from(Buffer.from(d.cek, 'base64')), { name: 'AES-GCM' }, true, ['encrypt', 'decrypt'])
      }
      const k = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt'])
      const raw = new Uint8Array(await crypto.subtle.exportKey('raw', k))
      escribir({ ...(d || { v: 1, data: {} }), cek: Buffer.from(raw).toString('base64'), devices: d?.devices || [] })
      return k
    },
  }
}

test('vault-passwords: el archivo queda CIFRADO en reposo, con la llave dentro', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'vault-pw-'))
  t.after(() => rm(dir, { recursive: true, force: true }))

  const p = piezasDelVault(dir)
  const desk = createPasswordDesk({
    client: red().cliente('X'), store: p.store, cek: await p.key(), isAllowed: () => false,
  })
  await desk.vault.put({ title: 'Banco', sites: ['banco.com.ec'], username: 'seyacat', secret: 's3cr3t' })

  // Lo que queda en disco no se puede leer sin la clave de la máquina.
  const crudo = await readFile(p.file, 'utf8')
  for (const dato of ['s3cr3t', 'seyacat', 'banco.com.ec', 'Banco']) {
    assert.ok(!crudo.includes(dato), `«${dato}» quedó legible en el archivo`)
  }

  // Y abriéndolo, tampoco: la entrada va cifrada con la CEK, aparte del cifrado en reposo.
  const abierto = JSON.stringify(p.leer())
  assert.ok(!abierto.includes('s3cr3t'), 'la contraseña se ve al abrir el archivo')
  assert.ok(abierto.includes('banco.com.ec'), 'los sitios sí van en claro dentro (hacen falta para emparejar)')
})

test('vault-passwords: la llave nace UNA vez y sobrevive al reinicio', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'vault-pw-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const p = piezasDelVault(dir)

  const primera = await p.key()
  const desk1 = createPasswordDesk({ client: red().cliente('A'), store: p.store, cek: primera, isAllowed: () => false })
  const { id } = await desk1.vault.put({ title: 'X', sites: ['x.com'], secret: 'hunter2' })

  // Segundo arranque: se relee la misma llave, así que la bóveda se abre.
  const segunda = await p.key()
  const desk2 = createPasswordDesk({ client: red().cliente('B'), store: p.store, cek: segunda, isAllowed: () => false })
  assert.equal((await desk2.vault.get(id)).secret, 'hunter2', 'la llave cambió entre arranques')
})

test('vault-passwords: hacen falta LAS DOS condiciones (lista del vault y acta)', async (t) => {
  const dir = await mkdtemp(join(tmpdir(), 'vault-pw-'))
  t.after(() => rm(dir, { recursive: true, force: true }))
  const p = piezasDelVault(dir)
  p.setDevice('APARATO', 'Chrome')

  // La comprobación tal cual la hace `vault.js`.
  const isAllowed = (acta) => (pub) =>
    p.devices().some(d => d.pubkey === pub) && (acta?.members || []).some(m => m.pub === pub)

  const conActa = isAllowed({ members: [{ pub: 'APARATO' }] })
  assert.equal(conActa('APARATO'), true)
  assert.equal(conActa('OTRO'), false, 'bastaba con estar en el acta')

  // Revocarlo en el acta le corta el acceso aunque siga en la lista del vault: no hay
  // que acordarse de quitarlo en dos sitios.
  const revocado = isAllowed({ members: [] })
  assert.equal(revocado('APARATO'), false, 'revocar en el acta no le cortó las contraseñas')
})
