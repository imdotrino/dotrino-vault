/**
 * La bóveda de CONTRASEÑAS atendida por el vault — LA QUE EL VAULT NO PUEDE LEER.
 *
 * Lo que se prueba aquí no es el formato (eso es de `@dotrino/passmanager`, que trae sus
 * propios tests) sino lo que pone el vault: el ACTA decide quién pide y a quién se le
 * envuelve cada llave, la aprobación es la del teléfono, y la bitácora es la misma que
 * audita firmas y enrolamientos.
 *
 * Y sobre todo lo que cambió en 0.123: **el archivo ya no lleva ninguna llave dentro**.
 * Hasta entonces `passwords.json` guardaba la `cek` de la bóveda cifrada con la llave de la
 * MÁQUINA, así que el demonio con el perfil cerrado descifraba igual y una copia del disco
 * abría todas las contraseñas. Las tres últimas pruebas son justo esa inversión.
 */
import { test } from 'node:test'
import assert from 'node:assert/strict'

import { createPasswordDesk, convertPasswords } from '../src/passwords.js'
import { SealedVault, ProxyTransport, makeEncKeypair, seal, open, isSealed, CODES } from '@dotrino/passmanager'
import { openWrap, decryptWithCek } from '@dotrino/identity/content'
import { makeDeviceKey, signWithDevice } from '@dotrino/identity/capabilities'

/**
 * Red de mentira que imita al cliente de verdad: sella al enviar, abre al entregar.
 *
 * Y como el de verdad, **el token NO es la llave**: se entrega desde un token y la llave de
 * quien envía viaja aparte, en `meta.fromPubkey`. Antes el token era la propia llave, y eso
 * escondía que el responder leía un campo que no existe (`meta.pubkey`): aquí contestaba y
 * en producción la bóveda no sabía a quién sellar la respuesta.
 */
function red () {
  const porLlave = new Map()
  const porToken = new Map()
  let n = 0
  function cliente (pubkey) {
    const handlers = []
    const token = `tok-${++n}`
    const c = {
      pubkey,
      token,
      encPrivate: null,
      // Un token no dice de quién es hasta que alguien saluda: aquí nadie saluda.
      pubkeyOfToken: () => null,
      on (ev, fn) { if (ev === 'message') handlers.push(fn) },
      off (ev, fn) { const i = handlers.indexOf(fn); if (i >= 0) handlers.splice(i, 1) },
      async sendSealed (dests, payload, { peerEncPub } = {}) {
        if (!peerEncPub) throw Object.assign(new Error('sin llave'), { code: CODES.UNSEALED })
        c.sendByPubkey(dests, await seal(payload, peerEncPub))
      },
      async sendSealedTo (destToken, payload, { peerEncPub } = {}) {
        if (!peerEncPub) throw Object.assign(new Error('sin llave'), { code: CODES.UNSEALED })
        const sobre = await seal(payload, peerEncPub)
        const destino = porToken.get(destToken)
        if (destino) setTimeout(() => destino._deliver(token, pubkey, sobre), 0)
      },
      sendByPubkey (dests, payload) {
        for (const d of [].concat(dests)) {
          const destino = porLlave.get(d)
          if (destino) setTimeout(() => destino._deliver(token, pubkey, payload), 0)
        }
      },
      async _deliver (fromToken, fromPubkey, payload) {
        if (isSealed(payload)) {
          if (!c.encPrivate) return
          let abierto
          try { abierto = await open(payload, c.encPrivate) } catch { return }
          for (const h of handlers) h(fromToken, abierto, { fromPubkey, sealed: true })
          return
        }
        for (const h of handlers) h(fromToken, payload, { fromPubkey, sealed: false })
      },
    }
    porLlave.set(pubkey, c)
    porToken.set(token, c)
    return c
  }
  return { cliente }
}

function memStore () {
  const m = new Map()
  const s = { async get (k) { return m.get(k) }, async set (k, v) { m.set(k, v) }, _raw: m }
  return s
}

/** Un aparato del acta: firma con su llave y abre lo que le envuelven con la suya. */
async function aparatoDelActa () {
  const firma = await makeDeviceKey({ label: 'gestor' })
  const cifra = await makeEncKeypair()
  return {
    pub: firma.publickey,
    encPub: cifra.encPub,
    encPrivate: cifra.privateKey,
    identity: {
      publickey: firma.publickey,
      sign: (body) => signWithDevice({ privateJwk: firma.privateJwk, publickey: firma.publickey, data: body }),
      async openSealed ({ wrap, envelope }) {
        const cek = await openWrap({ wrap, myEncPrivateKey: cifra.privateKey })
        return decryptWithCek({ cek, envelope })
      }
    }
  }
}

/** La copia de recuperación: la que abre la frase del perfil. */
async function recuperacion () {
  const r = await makeEncKeypair()
  return { encPub: r.encPub, privateKey: r.privateKey }
}

async function montar (extra = {}) {
  const net = red()
  const ap = await aparatoDelActa()
  const boveda = net.cliente('VAULT')
  const aparato = net.cliente(ap.pub)
  const rec = await recuperacion()

  const encVault = await makeEncKeypair()
  boveda.encPrivate = encVault.privateKey
  aparato.encPrivate = ap.encPrivate

  const bitacora = []
  const avisos = []
  const store = memStore()

  const desk = createPasswordDesk({
    client: boveda,
    store,
    // EL ACTA es quien decide, no este módulo. Y la bóveda NO está en la lista.
    members: (kind) => (kind === 'passkeys' && extra.sinPasskeys ? [] : [{ pub: ap.pub, encPub: ap.encPub }]),
    recoveryPub: () => rec.encPub,
    canWrite: (pub) => pub === ap.pub,
    isAllowed: (pub) => pub === ap.pub,
    encPubOf: (pub) => (pub === ap.pub ? ap.encPub : null),
    needsApproval: async () => true,
    // `audit` primero y el resto DESPUÉS pisaría el nombre: la bitácora del vault anota
    // `passwords` como operación y el `op` del gestor va dentro. Se guardan los dos.
    audit: (op, info) => bitacora.push({ audit: op, ...info }),
    approve: async (r) => { avisos.push(r.pubkey); return true },
    ...extra,
  }).start()

  const remota = new SealedVault(new ProxyTransport({
    client: aparato, peerPubkey: 'VAULT', peerEncPub: encVault.encPub, timeoutMs: 1500,
  }), { identity: ap.identity })

  // La llave del perfil la estrena quien convierte; aquí, el propio aparato.
  await remota.initProfileKey()
  await remota.put({ title: 'Salesforce', sites: ['salesforce.com'], username: 'sandrade@dotrino.com', secret: 'hunter2' })
  await remota.put({
    type: 'data',
    title: 'Mis datos',
    sites: ['datos.ejemplo'],
    fields: [
      { kind: 'tel', label: 'Teléfono', value: '0999111222' },
      { label: 'Cédula', value: '1700123456', private: true },
    ],
  })
  avisos.length = 0
  return { desk, remota, bitacora, avisos, net, store, ap, rec }
}

test('vault-passwords: un aparato del acta pide de a una', async () => {
  const { remota } = await montar()
  const hits = await remota.find('https://salesforce.com/login')
  assert.equal(hits.length, 1)
  assert.equal(hits[0].hint, 'sandrade@dotrino.com')

  const cred = await remota.get(hits[0].id, { keys: ['username', 'secret'] })
  assert.equal(cred.secret, 'hunter2')
})

test('vault-passwords: un aparato que el acta no reconoce no recibe nada', async () => {
  // Se monta con el permiso puesto —hay que poder guardar algo— y se le quita después,
  // que es lo que pasa de verdad: `caps <ID> -contrasenas`, y a la siguiente pasada deja
  // de recibir. La bóveda mira el acta en cada petición, no al conectarse.
  let permitido = true
  const { remota } = await montar({ isAllowed: () => permitido })
  permitido = false
  // Por CÓDIGO: «este aparato no puede» es `denied`. Antes cruzaba sin código.
  await assert.rejects(() => remota.find('https://salesforce.com/'), (e) => e.code === 'denied')
})

test('vault-passwords: la aprobación es la del vault (el teléfono), una por aparato', async () => {
  const { remota, avisos } = await montar()
  const [entrada] = await remota.find('https://salesforce.com/')
  await remota.get(entrada.id, { keys: ['secret'] })
  await remota.get(entrada.id, { keys: ['secret'] })
  assert.equal(avisos.length, 1, 'se pidió el dedo encima dos veces para el mismo aparato')
})

test('vault-passwords: un dato PÚBLICO no molesta al teléfono', async () => {
  const { remota, avisos } = await montar()
  const [datos] = await remota.find('https://datos.ejemplo/')
  const r = await remota.get(datos.id, { keys: ['tel'] })
  assert.ok(JSON.parse(r.fields).some((f) => f.value === '0999111222'))
  assert.equal(avisos.length, 0, 'rellenar un teléfono público pidió aprobación')
})

test('vault-passwords: y un dato PRIVADO sí, y llega solo él', async () => {
  const { remota, avisos } = await montar()
  const [datos] = await remota.find('https://datos.ejemplo/')
  const r = await remota.get(datos.id, { keys: ['label:Cédula'] })
  assert.equal(avisos.length, 1, 'un campo marcado privado salió sin preguntar')
  const campos = JSON.parse(r.fields)
  assert.deepEqual(campos.map((f) => f.value), ['1700123456'], 'llegó algo más que lo pedido')
})

test('vault-passwords: guardar encima no molesta al teléfono, y no pierde nada', async () => {
  const { remota, avisos } = await montar()
  const [entrada] = await remota.find('https://salesforce.com/')
  await remota.patch(entrada.id, { username: 'otro@dotrino.com' })
  assert.equal(avisos.length, 0, 'cambiar el usuario pidió aprobación: algo lee de más')

  const r = await remota.get(entrada.id, { keys: ['username', 'secret'] })
  assert.equal(r.username, 'otro@dotrino.com')
  assert.equal(r.secret, 'hunter2', 'se perdió la contraseña al cambiar el usuario')
})

test('vault-passwords: sin el visto bueno del teléfono, no sale la credencial', async () => {
  const { remota } = await montar({ approve: async () => false })
  const [entrada] = await remota.find('https://salesforce.com/')
  // «El teléfono dijo que no» es `not-approved`, distinto de `denied`: se arregla volviendo a pedir.
  await assert.rejects(() => remota.get(entrada.id, { keys: ['secret'] }), (e) => e.code === 'not-approved')
})

test('vault-passwords: la bitácora apunta la operación, NUNCA qué credencial', async () => {
  const { remota, bitacora } = await montar()
  const [entrada] = await remota.find('https://salesforce.com/')
  await remota.get(entrada.id, { keys: ['secret'] })
  const texto = JSON.stringify(bitacora)
  assert.ok(bitacora.some((b) => b.audit === 'passwords' && b.op === 'pm2.get'))
  for (const secreto of ['hunter2', 'salesforce.com', 'sandrade@dotrino.com']) {
    assert.ok(!texto.includes(secreto), `la bitácora se llevó «${secreto}»`)
  }
})

test('vault-passwords: ni el vault le deja listar la bóveda a un aparato', async () => {
  const { remota } = await montar()
  // `pm2.views` SÍ existe —es lo que sustituye a buscar dentro de la bóveda—, pero solo
  // devuelve VISTAS, y solo las que ese aparato puede abrir. Ni un valor sale de ahí.
  const vistas = await remota.list()
  assert.equal(vistas.length, 2)
  for (const v of vistas) {
    assert.ok(!('secret' in v) || !v.secret, 'una vista trajo un valor')
    assert.ok(!JSON.stringify(v).includes('hunter2'))
  }
})

test('EL ARCHIVO YA NO LLEVA NINGUNA LLAVE DENTRO (era el agujero)', async () => {
  const { store } = await montar()
  const crudo = JSON.stringify([...store._raw.entries()])
  // Ni los valores…
  for (const secreto of ['hunter2', 'sandrade@dotrino.com', '1700123456', 'Salesforce', 'salesforce.com']) {
    assert.ok(!crudo.includes(secreto), `«${secreto}» está en claro en el disco de la bóveda`)
  }
  // …ni la `cek` de antes: lo único guardado son sobres y envolturas.
  const sellado = await store.get('passmanager/sealed/v2')
  assert.ok(sellado.keyring.length > 0 && sellado.entries.length === 2)
  assert.equal(sellado.cek, undefined, 'la bóveda se guardó una llave')
  for (const g of sellado.keyring) {
    assert.ok(g.wraps['#recovery'], 'una generación sin copia de recuperación nace ilegible')
    for (const [quien, w] of Object.entries(g.wraps)) {
      assert.ok(w.epk && w.iv && w.ct, `la envoltura de ${quien} no es una envoltura`)
    }
  }
})

test('A LA BÓVEDA NO SE LE ENVUELVE NADA: sus llaves no están entre los destinatarios', async () => {
  const { store, ap } = await montar()
  const sellado = await store.get('passmanager/sealed/v2')
  const destinatarios = new Set()
  for (const g of sellado.keyring) for (const k of Object.keys(g.wraps)) destinatarios.add(k)
  assert.deepEqual([...destinatarios].sort(), ['#recovery', ap.pub].sort(),
    'alguien más recibió envoltura: si es una llave de esta máquina, el agujero sigue abierto')
})

test('CON EL PERFIL CERRADO la bóveda sigue atendiendo, y sigue sin poder leer', async () => {
  const { desk, remota, bitacora } = await montar()
  // Cerrar el perfil ya no cierra nada aquí: no hay ninguna llave que cerrar. Lo que
  // protege las contraseñas es que los sobres van a los aparatos, no el candado.
  desk.lock()
  const [entrada] = await remota.find('https://salesforce.com/')
  assert.equal((await remota.get(entrada.id, { keys: ['secret'] })).secret, 'hunter2')
  assert.ok(bitacora.some((b) => b.audit === 'passwords.lock' && b.sealed === true))
})

test('la conversión pasa lo viejo al formato sellado y BORRA la llave de antes', async () => {
  const { makeVaultKey, sealEntry } = await import('@dotrino/passmanager')
  const net = red()
  const ap = await aparatoDelActa()
  const rec = await recuperacion()
  const store = memStore()

  // Una bóveda como la de antes: entradas cifradas con UNA llave, y la llave al lado.
  const cek = await makeVaultKey()
  await store.set('passmanager/entries/v1', [
    await sealEntry(cek, { id: 'vieja', title: 'Banco', sites: ['banco.ec'], username: 'ana', secret: 'la de antes' })
  ])
  let llaveBorrada = false

  const boveda = net.cliente('VAULT')
  const encVault = await makeEncKeypair()
  boveda.encPrivate = encVault.privateKey
  const desk = createPasswordDesk({
    client: boveda,
    store,
    members: () => [{ pub: ap.pub, encPub: ap.encPub }],
    recoveryPub: () => rec.encPub,
    canWrite: (pub) => pub === ap.pub,
    isAllowed: (pub) => pub === ap.pub,
    encPubOf: (pub) => (pub === ap.pub ? ap.encPub : null),
    approve: async () => true,
  }).start()

  const r = await convertPasswords({
    store,
    sealed: desk.sealed,
    cek,
    recipients: { recoveryPub: rec.encPub, main: [{ pub: ap.pub, encPub: ap.encPub }], passkeys: [{ pub: ap.pub, encPub: ap.encPub }] },
    author: { publickey: ap.pub, sign: (body) => ap.identity.sign(body) },
    dropOldKey: () => { llaveBorrada = true }
  })

  assert.equal(r.entries, 1)
  assert.equal(llaveBorrada, true, 'la llave vieja se quedó en el disco: el agujero sigue abierto')
  assert.deepEqual(await store.get('passmanager/entries/v1'), [], 'quedaron las entradas del formato viejo')

  // Y el aparato la abre con SU llave, que es lo que antes no podía.
  const net2 = net.cliente(ap.pub)
  net2.encPrivate = ap.encPrivate
  const remota = new SealedVault(new ProxyTransport({
    client: net2, peerPubkey: 'VAULT', peerEncPub: encVault.encPub, timeoutMs: 1500
  }), { identity: ap.identity })
  const [entrada] = await remota.find('https://banco.ec/')
  assert.equal(entrada.title, 'Banco')
  assert.equal((await remota.get('vieja', { keys: ['secret'] })).secret, 'la de antes')
})

test('un aparato que entra DESPUÉS no lee nada hasta que se le reparte, y al abrir se le reparte', async () => {
  const { desk, store, rec } = await montar()
  const nuevo = await aparatoDelActa()

  // Todavía no tiene envoltura de nada: la bóveda no le cuenta ni que existen.
  assert.deepEqual(await desk.sealed.views({ pub: nuevo.pub }), [])

  // Al abrir el perfil, la copia de recuperación paga la deuda (§2.5). El acta ahora
  // nombra al aparato nuevo y ya no al de antes: se le envuelve lo suyo y se retira lo
  // del que salió, todo sin abrir un solo valor.
  desk.sealed.recipients = () => [{ pub: nuevo.pub, encPub: nuevo.encPub }]
  const r = await desk.sealed.rewrapAll({
    openRecovery: async (wrap) => openWrap({ wrap, myEncPrivateKey: rec.privateKey })
  })
  assert.ok(r.wrapped > 0, 'no se le envolvió nada al aparato nuevo')
  assert.ok(r.dropped > 0, 'no se retiró la envoltura del que ya no está en la lista')
  assert.equal((await desk.sealed.views({ pub: nuevo.pub })).length, 2)
  assert.ok(store)
})
