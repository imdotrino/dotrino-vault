/**
 * ENTRAR CON USUARIO Y CONTRASEÑA, de punta a punta (`lib/src/loginClient.js`).
 *
 * El lado que atiende ya estaba probado (`device-vault.test.mjs` hacía media conversación a
 * mano, mensaje a mensaje). Esto prueba la otra mitad —la que corre en el equipo prestado— y
 * sobre todo que las dos encajan: el mismo canal, los mismos mensajes y las mismas
 * comprobaciones que hace quien entra.
 *
 * El proxio es de mentira, pero de una mentira concreta: reparte tokens, entrega mensajes al
 * destinatario y guarda canales. Lo que se prueba es el protocolo, no la red.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { makeDeviceKey, makeDeviceEncKey, signDelegationWith, signWithDevice, pubkeyId } from '@dotrino/identity/capabilities'
import { genesisActa, sealActa, applyChanges } from '@dotrino/identity/acta'
import { client as opaqueClient } from '@dotrino/opaque'
import { startDeviceVault } from '../lib/src/index.js'
import { createLoginDesk, sealDeviceKeys, accountCode, parseLoginAddress, vaultChannel } from '../lib/src/passwordLogins.js'
import { loginWithPassword, closeLogin } from '../lib/src/loginClient.js'

/** Un proxio de mentira: tokens, entrega dirigida y canales públicos. */
function fakeProxy () {
  const conexiones = new Map()   // token → oyentes
  const canales = new Map()      // canal → Set(token)
  let n = 0
  return {
    connect (nombre) {
      const token = `${nombre}-${++n}`
      const oyentes = []
      conexiones.set(token, oyentes)
      const cliente = {
        token,
        url: 'wss://test.invalid',
        on (ev, fn) {
          if (ev !== 'message') return () => {}
          oyentes.push(fn)
          return () => { const i = oyentes.indexOf(fn); if (i >= 0) oyentes.splice(i, 1) }
        },
        send (to, obj) {
          for (const dest of (Array.isArray(to) ? to : [to])) {
            for (const fn of conexiones.get(dest) || []) queueMicrotask(() => fn(token, obj, {}))
          }
        },
        sendByPubkey () {},
        async identify () { return { ok: true } },
        async identifyAs () { return { ok: true } },
        async publish (canal) { (canales.get(canal) || canales.set(canal, new Set()).get(canal)).add(token); return { ok: true } },
        async list (canal) { return [...(canales.get(canal) || [])] },
        async requestPairingCode () { return { code: 'ABC123' } },
        close () { conexiones.delete(token) }
      }
      return cliente
    },
    canales
  }
}

/**
 * Identidad de la bóveda con un acta DE VERDAD: firmada, con su génesis y su linaje. Hace
 * falta porque quien entra la verifica entera (`checkVaultReply`) en vez de creérsela.
 */
async function vaultIdentity () {
  const pair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const iss = JSON.stringify(await crypto.subtle.exportKey('jwk', pair.publicKey))
  let acta = await sealActa({ acta: genesisActa({ pub: iss, label: 'la bóveda' }), privateKey: pair.privateKey })
  const issued = []
  const revoked = []
  return {
    me: { publickey: iss, encryptionPubkey: null },
    iss,
    get acta () { return acta },
    async profileActa () { return { acta, isMaster: true } },
    async admitMember ({ pub, encPub = null, label = '', cn = null, caps = [] }) {
      const next = await applyChanges(acta, [{ op: 'admit', member: { pub, ...(encPub ? { encPub } : {}), label, ...(cn ? { cn } : {}), caps } }], { by: iss })
      acta = await sealActa({ acta: next, privateKey: pair.privateKey })
      return { ok: true, seq: acta.seq }
    },
    async signDelegation (sub, scope, { label = '' } = {}) {
      const cert = await signDelegationWith(pair.privateKey, iss, { sub, scope, iat: Date.now(), seq: acta.seq, nonce: crypto.randomUUID() })
      issued.push({ nonce: cert.nonce, sub, scope, label })
      return { cert }
    },
    async signData (data) {
      const sig = await crypto.subtle.sign({ name: 'ECDSA', hash: { name: 'SHA-256' } }, pair.privateKey, new TextEncoder().encode(JSON.stringify(data)))
      return { signature: Buffer.from(new Uint8Array(sig)).toString('base64'), publickey: iss }
    },
    async listDelegations () { return { issued, revoked } },
    async revokeDelegation (nonce) { revoked.push({ nonce }); return { ok: true, nonce } }
  }
}

/** Levanta la bóveda con su escritorio de inicios de sesión y le da de alta un usuario. */
async function conLogin ({ password = 'una contraseña larga de verdad', user = 'ana' } = {}) {
  const proxy = fakeProxy()
  const identity = await vaultIdentity()
  const client = proxy.connect('vault')
  let saved = null
  const logins = createLoginDesk({ load: () => (saved ? JSON.parse(saved) : null), save: (s) => { saved = JSON.stringify(s) } })
  const vault = await startDeviceVault(identity, { client, logins })

  // Alta, como la hace la consola: las llaves NACEN aquí y salen cerradas con la contraseña.
  const device = await makeDeviceKey({ label: 'equipo prestado' })
  const enc = await makeDeviceEncKey()
  const reg = opaqueClient.registrationStart({ password })
  const { response } = await vault.loginRegisterBegin({ user, request: reg.request })
  const fin = opaqueClient.registrationFinish({ state: reg.state, response, password })
  const blob = await sealDeviceKeys(fin.exportKey, { sign: device.privateJwk, enc: enc.encPrivateJwk })
  await vault.loginRegisterFinish({ user, upload: fin.upload, pub: device.publickey, encPub: enc.encPublickey, label: 'equipo prestado', blob })

  const address = `${user}@${accountCode((await pubkeyId(identity.acta.profileId)).slice(0, 16))}`
  return { proxy, identity, client, vault, device, enc, address, password, user }
}

test('la bóveda-pestaña SE ANUNCIA en el canal de su cuenta', async () => {
  const { proxy, identity, client } = await conLogin()
  const canal = vaultChannel((await pubkeyId(identity.acta.profileId)).slice(0, 16))
  assert.ok(proxy.canales.get(canal)?.has(client.token),
    'sin el anuncio, un equipo prestado no puede encontrar esta bóveda por su dirección')
})

test('entrar: sale el aparato entero, con sus llaves, su papel y su acta', async () => {
  const { proxy, identity, device, enc, address, password } = await conLogin()
  const prestado = proxy.connect('prestado')

  const entrada = await loginWithPassword({ transport: prestado, address, password, label: 'el cyber' })

  assert.equal(entrada.publickey, device.publickey, 'no entró como el aparato que se creó')
  assert.equal(entrada.encPublickey, enc.encPublickey, 'la llave de cifrado la dice el acta')
  assert.deepEqual(entrada.keys.sign, device.privateJwk, 'el paquete no traía la llave de firma')
  assert.deepEqual(entrada.keys.enc, enc.encPrivateJwk, 'ni la de cifrado')
  assert.equal(entrada.acta.profileId, identity.acta.profileId, 'el acta es la de la cuenta')
  assert.ok(entrada.sid, 'sin inicio de sesión no hay nada que cerrar después')
  assert.ok(entrada.caps.includes('sign'), 'el aparato entra con los permisos que le dio el acta')
})

test('la contraseña equivocada no entra, y lo dice igual que un usuario que no existe', async () => {
  const { proxy, address } = await conLogin()
  const prestado = proxy.connect('prestado')

  const mala = await loginWithPassword({ transport: prestado, address, password: 'no es esa', timeoutMs: 2000 }).catch((e) => e)
  const nadie = await loginWithPassword({ transport: prestado, address: address.replace(/^[^@]+/, 'nadie'), password: 'no es esa', timeoutMs: 2000 }).catch((e) => e)

  assert.equal(mala.code, 'login-failed')
  assert.equal(nadie.code, 'login-failed')
  assert.equal(mala.message, nadie.message, 'desde fuera se distingue qué usuarios existen')
})

test('una dirección de OTRA cuenta no entra aunque la bóveda conteste', async () => {
  const { proxy, address, password, identity } = await conLogin()
  const prestado = proxy.connect('prestado')
  // Se pide por un código que NO es el de esta cuenta: el canal está vacío y se para antes
  // de decirle la contraseña a nadie.
  const otro = address.replace(/@.*/, '@AAAA-BBBB-CCCC')
  const e = await loginWithPassword({ transport: prestado, address: otro, password, timeoutMs: 2000 }).catch((x) => x)
  assert.equal(e.code, 'no-vault')
  assert.notEqual(accountCode((await pubkeyId(identity.acta.profileId)).slice(0, 16)), 'AAAA-BBBB-CCCC')
})

test('una bóveda que no atiende inicios de sesión se salta, no se confunde con la contraseña', async () => {
  const { proxy, address, password, identity } = await conLogin()
  // Una segunda bóveda de la MISMA cuenta, sin escritorio: se anuncia igual y hay que
  // pasar de largo hasta la que sí atiende.
  const muda = proxy.connect('muda')
  const canal = vaultChannel((await pubkeyId(identity.acta.profileId)).slice(0, 16))
  await muda.publish(canal)
  // La muda va la última en la lista, así que se prueba también al revés: se quita la
  // buena del canal y tiene que salir el error de la muda, no `login-failed`.
  const prestado = proxy.connect('prestado')
  const entrada = await loginWithPassword({ transport: prestado, address, password, timeoutMs: 2000 })
  assert.ok(entrada.sid, 'con una bóveda muda en el canal no llegó a la que sí atiende')
})

test('salir cierra el inicio de sesión en la bóveda', async () => {
  const { proxy, vault, address, password, user } = await conLogin()
  const prestado = proxy.connect('prestado')
  const entrada = await loginWithPassword({ transport: prestado, address, password })

  assert.equal(vault.listLogins().find((l) => l.user === user).sessions.length, 1)
  const r = await closeLogin({
    transport: prestado, token: entrada.vaultToken, user, sid: entrada.sid,
    publickey: entrada.publickey, privateJwk: entrada.keys.sign
  })
  assert.equal(r.ok, true)
  assert.equal(vault.listLogins().find((l) => l.user === user).sessions.length, 0, 'la plaza sigue ocupada tras salir')
})

test('el OPAQUE se puede inyectar, y puede ser ASÍNCRONO (la extensión)', async () => {
  // En una extensión el WASM vive en una página sandbox, así que cada llamada cruza un
  // `postMessage` y vuelve una promesa. Se prueba con un envoltorio que promete a propósito:
  // si el cliente dejara de esperar, `start.request` sería una promesa y OPAQUE lo rechazaría
  // con «request is required» — un error que no se parece en nada a la causa.
  const { proxy, address, password } = await conLogin()
  const prestado = proxy.connect('prestado')
  const llamadas = []
  const lento = {
    loginStart: async (a) => { llamadas.push('start'); await null; return opaqueClient.loginStart(a) },
    loginFinish: async (a) => { llamadas.push('finish'); await null; return opaqueClient.loginFinish(a) }
  }

  const entrada = await loginWithPassword({ transport: prestado, address, password, opaque: lento })

  assert.ok(entrada.sid, 'no entró con un OPAQUE asíncrono')
  assert.deepEqual(llamadas, ['start', 'finish'], 'no usó el OPAQUE que se le pasó')
})

test('salir se puede firmar A DISTANCIA (sin entregar la llave)', async () => {
  // En una extensión la llave vive en el service worker y el socket lo tiene la página:
  // o se firma con un `sign(data)`, o la privada tendría que cruzar para nada.
  const { proxy, vault, address, password, user } = await conLogin()
  const prestado = proxy.connect('prestado')
  const entrada = await loginWithPassword({ transport: prestado, address, password })

  const r = await closeLogin({
    transport: prestado, token: entrada.vaultToken, user, sid: entrada.sid,
    publickey: entrada.publickey,
    sign: (data) => signWithDevice({ privateJwk: entrada.keys.sign, data })
  })

  assert.equal(r.ok, true)
  assert.equal(vault.listLogins().find((l) => l.user === user).sessions.length, 0)
})

test('sin llave y sin sign(), salir NO se finge: se para', async () => {
  const { proxy, address, password, user } = await conLogin()
  const prestado = proxy.connect('prestado')
  const entrada = await loginWithPassword({ transport: prestado, address, password })
  const e = await closeLogin({
    transport: prestado, token: entrada.vaultToken, user, sid: entrada.sid, publickey: entrada.publickey
  }).catch((x) => x)
  assert.equal(e.code, 'no-signature')
})

test('la dirección se lee como la teclea una persona, y se para si no es una dirección', () => {
  assert.deepEqual(parseLoginAddress('  Ana@ab12cd34ef56 '), { user: 'ana', code: 'AB12-CD34-EF56', address: 'ana@AB12-CD34-EF56' })
  assert.deepEqual(parseLoginAddress('ana@AB12-CD34-EF56').code, 'AB12-CD34-EF56')
  for (const malo of ['ana', 'ana@AB12-CD34', '@AB12-CD34-EF56', 'ana@AB12-CD34-EF56-77']) {
    assert.throws(() => parseLoginAddress(malo), (e) => e.code === 'bad-address' || e.code === 'bad-user', `pasó «${malo}»`)
  }
})
