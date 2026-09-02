/**
 * E2E de SECRETOS de servicios: proxy real (repo hermano dotrino-proxy) +
 * daemon del vault + cliente de servicio (@dotrino/vault/service).
 *
 *   vault: secret set proxy TURN_KEY_ID …  →  pair --service proxy
 *   servicio: enrollService (aprobación programática) → fetchSecrets
 *
 * Correr:  npm test   (node --test test/)
 */
import { test, before, after } from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { fileURLToPath } from 'node:url'
import { signWithDevice } from '@dotrino/identity/capabilities'

const require = createRequire(import.meta.url)
const proxyServerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dotrino-proxy', 'server.js')

const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))

/**
 * Enrolar Y esperar a que el permiso esté puesto.
 *
 * `enrollService` termina en cuanto llega el papel, que es ANTES de que `setCaps` acabe:
 * pedir los secretos justo después era una carrera que a veces perdía. El envoltorio
 * espera las dos cosas, así que el test comprueba lo que quiere comprobar y no el reloj.
 */
async function enrolar (opts) {
  // Se importa AQUÍ: en este fichero `enrollService` entra por un `import()` dentro de
  // cada test, así que a nivel de módulo no existe.
  const { enrollService } = await import('../lib/src/service.js')
  let permiso = null
  const r = await enrollService({ ...opts, onCode: ({ code }) => { permiso = aprobarYPermitir(code) } })
  await permiso
  return r
}

/**
 * Aprobar el emparejamiento Y concederle `unattended`.
 *
 * Desde 2026-09-01 recibir claves privadas SIN aprobación es un permiso del acta, y el
 * defecto es pedirla: un servicio recién enrolado se queda esperando a que un aparato con
 * `approve` lo firme. Aquí no hay teléfono, así que sin esto CADA test de este fichero se
 * cuelga — que es, literalmente, lo que le pasa a un servicio de verdad al que no se le
 * concede. Se hace en el arnés y no en el pilar a propósito: que el permiso haya que darlo
 * es el punto, no un estorbo del que escaparse.
 */
async function aprobarYPermitir (code) {
  const r = await vault.approveDevice(code)
  const sub = r?.cert?.sub
  if (sub) {
    const m = (await vault.identity.profileActa()).acta.members.find((x) => x.pub === sub)
    await vault.setCaps(sub, [...new Set([...(m?.caps || []), 'unattended'])])
  }
  return r
}

let proxy, proxyUrl, vault, svcDir

before(async () => {
  process.env.NODE_ENV = 'test'
  process.env.PROXY_DB_FILE = ':memory:'
  // La ventana con la que la bóveda agrupa avisos (3 s en producción). Acortada para no
  // pasar el test entero esperando: lo que se comprueba es CUÁNTOS avisos salen, no cuándo.
  process.env.DOTRINO_VAULT_NOTICE_MS = '150'
  proxy = require(proxyServerPath)
  const port = await proxy.start(0)
  proxyUrl = `ws://127.0.0.1:${port}`

  const { startVault } = await import('../src/vault.js')
  // `VAULT_LOG=1` enciende el registro de la bóveda. Sin esta escotilla, un fallo aquí es
  // indiagnosticable: se ve que el servicio no puede abrir su cajón y nada más — la razón
  // («wrong password» al abrir la copia de recuperación, por ejemplo) la dice la bóveda en
  // un log que este arnés estaba tirando.
  vault = await startVault({ dir: tmp('vault-e2e-'), proxyUrl, log: process.env.VAULT_LOG ? console.error : () => {} })
  svcDir = tmp('svc-e2e-')
})

after(async () => {
  try { vault?.close() } catch (_) {}
  try { await proxy?.stop() } catch (_) {}
})

test('flujo completo: set → pair --service → enroll → fetchSecrets', async () => {
  await vault.setSecret('proxy', 'TURN_KEY_ID', 'k-123')
  await vault.setSecret('proxy', 'TURN_KEY_API_TOKEN', 't-456')
  // Se nace privada: el valor no sale de esta máquina mientras nadie diga lo contrario,
  // así que de estas dos la lista solo da el nombre.
  assert.deepEqual(vault.listSecrets(), {
    proxy: [{ key: 'TURN_KEY_ID', public: false }, { key: 'TURN_KEY_API_TOKEN', public: false }]
  })

  // pair --service proxy (mismo scope que arma el daemon)
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:proxy'], label: 'service:proxy', ttlMs: 24 * 60 * 60 * 1000 })

  const { enrollService, fetchSecrets, readServiceIdentity } = await import('../lib/src/service.js')
  const { device, cert } = await enrolar({
    qr, ns: 'proxy', dir: svcDir
  })
  assert.ok(device?.publickey && cert?.sig)
  assert.deepEqual(cert.scope, ['vault:secrets:proxy'])
  assert.equal(readServiceIdentity(svcDir)?.ns, 'proxy')

  const secrets = await fetchSecrets({ dir: svcDir })
  assert.deepEqual(secrets, { TURN_KEY_ID: 'k-123', TURN_KEY_API_TOKEN: 't-456' })
})

/**
 * PERMISOS, NO TIPOS (2026-08-22). Un aparato es un aparato y lo que puede hacer: un
 * bot que publica en las apps firma como aparato del acta (`vault:sign`) Y lee su
 * cajón (`vault:secrets:<ns>`), en UN solo cert y con UN solo enrolamiento. Y ese
 * enrolamiento (`enrollWithVault`) no persiste nada: quien lo llama decide dónde
 * vive la identidad, y los secretos se piden con ella por parámetros, sin `dir`.
 */
test('un cert con sign + secrets:<ns>: enrollWithVault no persiste y fetchSecrets abre con la identidad por parámetros', async () => {
  await vault.setSecret('eco', 'BUFFER_API_KEY', 'b-789')
  const { qr } = await vault.startPairing({ scope: ['vault:sign', 'vault:secrets:eco'], label: 'social-bot', ttlMs: 60000 })
  const { enrollWithVault, fetchSecrets } = await import('../lib/src/service.js')
  let permisoBot = null
  const link = await enrollWithVault({
    qr, label: 'social-bot', expectedScope: 'vault:secrets:eco',
    onCode: ({ code }) => { permisoBot = aprobarYPermitir(code) }
  })
  await permisoBot   // el papel llega antes que el permiso: esperar los dos
  assert.deepEqual(link.cert.scope, ['vault:sign', 'vault:secrets:eco'])
  assert.ok(link.device?.privateJwk && link.enc?.privateJwk && link.enc?.publickey, 'las dos llaves')
  // En el acta entra con TODAS sus capacidades (identity ≥ 0.57: permisos, no tipos):
  // el cajón no borra la firma.
  const me = (await vault.identity.profileActa()).acta.members.find((m) => m.pub === link.device.publickey)
  assert.ok(me, 'está en el acta')
  assert.equal(me.cn, 'eco')
  // `unattended` lo añade el arnés (`aprobarYPermitir`), no el emparejamiento: entrar NO
  // lo concede —como `admin`, se da a mano— y sin él este bot se quedaría esperando a un
  // teléfono. Aquí se ve el modelo entero: lo que trae la invitación y lo que decides tú.
  assert.deepEqual([...me.caps].sort(), ['secrets', 'sign', 'unattended'])
  assert.equal(link.iss, qr.iss)
  const secrets = await fetchSecrets({ ns: 'eco', proxyUrl, masterPubkey: link.iss, device: link.device, cert: link.cert, enc: link.enc })
  assert.deepEqual(secrets, { BUFFER_API_KEY: 'b-789' })
})

test('la lista da NOMBRES y visibilidad, nunca un valor: tampoco el de una pública', async () => {
  // CAMBIÓ LA REGLA (dueño, 2026-09-02): «las públicas igual, codificadas en sobres… la
  // única diferencia es si se despachan o no, son políticas; dales el mismo tratamiento de
  // seguridad». Antes una pública se guardaba en claro y esta lista enseñaba su valor.
  //
  // Ya no: `pública` dice a quién se le entrega SIN APROBACIÓN, no cómo se guarda. Para ver
  // un valor hay que poder abrirlo —y en un cajón con dueño, quien administra no puede, que
  // es exactamente lo que se quiso al quitarle esa envoltura.
  await vault.setSecret('escaparate', 'PUBLIC_URL', 'https://ejemplo.com', true)
  await vault.setSecret('escaparate', 'API_KEY', 's3cr3t')
  assert.deepEqual(vault.listSecrets().escaparate, [
    { key: 'PUBLIC_URL', public: true },
    { key: 'API_KEY', public: false }
  ])

  // El cajón por aparato va por la misma regla, y por el mismo camino.
  const pub = 'PUB-DE-UN-APARATO'
  await vault.secrets.setDevice(pub, 'PORT', '8443', true)
  await vault.secrets.setDevice(pub, 'DB_PASSWORD', 'nope')
  const row = (await vault.listDeviceSecrets()).find((d) => d.pub === pub)
  assert.deepEqual(row.keys, [
    { key: 'PORT', public: true },
    { key: 'DB_PASSWORD', public: false }
  ])
})

test('loadEnv() inyecta los secretos en process.env y PISA el .env', async () => {
  delete process.env.TURN_KEY_ID
  delete process.env.DOTRINO_ENV_OVERRIDE
  // Esto es lo que deja un `.env` cargado antes: un valor viejo ya en el entorno.
  // El vault tiene que ganarle, o rotar la llave no sirve de nada mientras quede
  // una copia rancia en la máquina.
  process.env.TURN_KEY_API_TOKEN = 'la-vieja-del-env'

  const { loadEnv } = await import('../lib/src/env.js')
  const { ns, injected, overridden, skipped } = await loadEnv({ ns: 'proxy', dir: svcDir, wait: false })

  assert.equal(ns, 'proxy')
  assert.equal(process.env.TURN_KEY_ID, 'k-123')
  assert.equal(process.env.TURN_KEY_API_TOKEN, 't-456', 'el vault manda sobre el entorno')
  assert.deepEqual(injected.sort(), ['TURN_KEY_API_TOKEN', 'TURN_KEY_ID'])
  assert.deepEqual(overridden, ['TURN_KEY_API_TOKEN'], 'se reporta lo pisado')
  assert.deepEqual(skipped, [])

  // La escotilla de depuración devuelve la precedencia clásica sin tocar código.
  process.env.TURN_KEY_API_TOKEN = 'la-del-operador'
  await loadEnv({ ns: 'proxy', dir: svcDir, wait: false, override: false })
  assert.equal(process.env.TURN_KEY_API_TOKEN, 'la-del-operador')

  // required: si falta una clave, no arranca
  await assert.rejects(
    loadEnv({ ns: 'proxy', dir: svcDir, wait: false, required: ['NO_EXISTE'] }),
    /missing secrets/
  )
})

test('enrolar acepta la invitación TAL COMO la imprime el vault (no JSON)', async () => {
  // `enrollService` hacía `JSON.parse` del string, pero el vault no imprime JSON
  // desde que existe la marca de formato: emite la URL del QR y el código
  // compacto. O sea que enrolar un servicio pegando lo que el vault te da fallaba
  // siempre con «qr inválido: no es JSON». No lo cazaba nadie porque el único
  // servicio enrolado del ecosistema lo hizo cuando el formato aún era JSON.
  const { encodeInvite, inviteUrl } = await import('../lib/src/invite.js')
  const { enrollService } = await import('../lib/src/service.js')

  for (const [nombre, comoLoDa] of [['código compacto', encodeInvite], ['URL del QR', inviteUrl]]) {
    const ns = nombre === 'código compacto' ? 'compacto' : 'urlqr'
    await vault.setSecret(ns, 'API_KEY', 'v-' + ns)
    const { qr } = await vault.startPairing({ scope: [`vault:secrets:${ns}`], label: 'service:' + ns, ttlMs: 60000 })
    const dir = tmp('svc-' + ns + '-')

    await enrolar({
      qr: comoLoDa(qr), ns, dir                        // ← un STRING, como lo pega un humano
    })
    assert.deepEqual(await fetchSecretsFrom(dir), { API_KEY: 'v-' + ns }, `falló pegando la ${nombre}`)
  }

  await assert.rejects(
    enrollService({ qr: 'esto no es una invitación', ns: 'proxy', dir: tmp('svc-basura-') }),
    /does not look like a vault invitation/
  )
})

test('un agente tiene UNA identidad: re-enrolar reemplaza y avisa qué descarta', async () => {
  // A diferencia de un aparato (que lleva varios perfiles y puede meter su cuenta
  // al vault por adopción), un agente no acumula identidades ni transfiere la
  // suya: el vault le cede una y la anterior deja de existir. Enrolar dos veces
  // no es un error a bloquear, es la forma de ROTAR la identidad de un agente.
  const { enrollService, readServiceIdentity } = await import('../lib/src/service.js')
  const { encodeInvite } = await import('../lib/src/invite.js')
  const ns = 'rotable'
  await vault.setSecret(ns, 'API_KEY', 'v1')
  const dir = tmp('svc-rot-')

  const enroll = async (onReplace) => {
    const { qr } = await vault.startPairing({ scope: [`vault:secrets:${ns}`], label: 'service:' + ns, ttlMs: 60000 })
    return enrolar({
      qr: encodeInvite(qr), ns, dir, onReplace
  })
  }

  const first = await enroll()
  assert.equal(first.replaced, null, 'la primera vez no hay nada que descartar')
  const oldKey = readServiceIdentity(dir).device.publickey

  let notified = null
  const second = await enroll((prev) => { notified = prev })
  assert.ok(notified, 're-enrolar tiene que avisar que descarta la identidad anterior')
  assert.equal(notified.ns, ns)
  assert.match(notified.deviceId, /^[0-9A-F]{8}$/)
  assert.deepEqual(second.replaced, notified)

  // Reemplazo, no convivencia: en disco queda UNA identidad, la nueva.
  const saved = readServiceIdentity(dir)
  assert.notEqual(saved.device.publickey, oldKey, 'la llave tiene que ser otra')
  assert.equal(saved.device.publickey, second.device.publickey)
  assert.deepEqual(await fetchSecretsFrom(dir), { API_KEY: 'v1' }, 'la identidad nueva sirve para leer')
})

test('un agente NUNCA adopta: el camino de transferir identidad se rechaza de entrada', async () => {
  // El emparejamiento tiene dos modos y los declara la bóveda en la invitación:
  // `join` (el que se enrola entra a la cuenta de la bóveda) y `adopt` (la bóveda
  // se queda con la cuenta que trae el aparato). El segundo es para APARATOS. Un
  // agente no transfiere identidad: la suya se la cede el vault, así que este
  // camino no se negocia. Y se corta ACÁ, al pegar la invitación, no después de
  // un viaje que termina en un «intent-mismatch» que no le explica nada a nadie.
  const { enrollService } = await import('../lib/src/service.js')
  const { encodeInvite } = await import('../lib/src/invite.js')
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:adoptame'], label: 'x', ttlMs: 60000, mode: 'adopt' })
  assert.equal(qr.m, 'adopt', 'la bóveda declara el modo en la propia invitación')

  await assert.rejects(
    enrollService({ qr: encodeInvite(qr), ns: 'adoptame', dir: tmp('svc-adopt-') }),
    /an agent does not transfer its identity/
  )
})

test('la bóveda AVISA al agente cuando su configuración cambia (agrupado)', async () => {
  // Guardar un secreto no sirve de nada si quien lo usa no se entera. El aviso no
  // lleva valores: solo dice «el ns cambió», y el agente reacciona saliendo para
  // que su supervisor lo levante limpio — así lee todo fresco y, sobre todo, el
  // valor viejo deja de existir en su memoria (en JS un string no se puede borrar).
  const { watchSecretsChanges } = await import('../lib/src/service.js')
  const notices = []
  const w = await watchSecretsChanges({
    dir: svcDir, ns: 'proxy', graceMs: 0, minIntervalMs: 0, jitterMs: 0,
    onChange: (i) => notices.push(i)
  })
  try {
    // Los tests anteriores también guardaron secretos de este ns, y su aviso
    // agrupado puede seguir en vuelo: se deja pasar la ventana y se cuenta desde
    // cero, o se estaría midiendo el eco de otra prueba.
    await new Promise((r) => setTimeout(r, 4000))
    notices.length = 0

    await vault.setSecret('proxy', 'TURN_KEY_ID', 'rotada-1')
    // AGRUPADO: tres escrituras seguidas son UN cambio de configuración, no tres.
    await vault.setSecret('proxy', 'TURN_KEY_API_TOKEN', 'rotada-2')
    await vault.setSecret('proxy', 'OTRA', 'rotada-3')

    await waitFor(() => notices.length > 0, 'el aviso de cambio')
    await new Promise((r) => setTimeout(r, 1500))
    assert.equal(notices.length, 1, 'tres `secret set` seguidos avisan UNA vez, no tres')
    assert.equal(notices[0].ns, 'proxy')
  } finally { w.stop() }
})

test('el aviso de otro namespace no le llega a este agente', async () => {
  const { watchSecretsChanges } = await import('../lib/src/service.js')
  const notices = []
  const w = await watchSecretsChanges({
    dir: svcDir, ns: 'proxy', graceMs: 0, minIntervalMs: 0, jitterMs: 0,
    onChange: (i) => notices.push(i)
  })
  try {
    // El aviso dice QUÉ ns cambió, así que mandárselo a un agente ajeno sería
    // contarle que ese namespace existe. Se manda solo a los del ns.
    await vault.setSecret('geo', 'DB_URL', 'nada-que-ver')
    await new Promise((r) => setTimeout(r, 1500))
    assert.equal(notices.length, 0, 'el agente del ns «proxy» no se entera de lo de «geo»')
  } finally { w.stop() }
})

test('un aviso mal firmado NO reinicia a nadie (sería un ataque de denegación)', async () => {
  // Es la defensa que hace que esto no sea un arma: si cualquiera pudiera mandar
  // el aviso, cualquiera podría reiniciar la flota ajena cuando quisiera.
  const { watchSecretsChanges } = await import('../lib/src/service.js')
  const { MSG } = await import('../lib/src/protocol.js')
  const { makeDeviceKey, signWithDevice } = await import('@dotrino/identity/capabilities')
  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')

  const notices = []
  const w = await watchSecretsChanges({
    dir: svcDir, ns: 'proxy', graceMs: 0, minIntervalMs: 0, jitterMs: 0,
    onChange: (i) => notices.push(i)
  })
  try {
    // Un impostor con llave propia y bien formada: firma de verdad, pero NO es la
    // maestra que este agente tiene pineada.
    const impostor = await makeDeviceKey({ label: 'impostor' })
    const c = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
    await c.connect()
    const body = { op: 'secrets.changed', ns: 'proxy', ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: impostor.privateJwk, data: body })
    const yo = await readServiceIdentitySync()
    c.sendByPubkey(yo.device.publickey, { type: MSG.SECRETS_CHANGED, body, signature })
    await new Promise((r) => setTimeout(r, 1500))
    c.close()
    assert.equal(notices.length, 0, 'un aviso que no viene de TU bóveda se ignora')
  } finally { w.stop() }
})

// El archivo va CIFRADO en reposo (ligado a la máquina), así que se lee por el
// mismo camino que el servicio, no con un JSON.parse a pelo.
async function readServiceIdentitySync () {
  const { readServiceIdentity } = await import('../lib/src/service.js')
  return readServiceIdentity(svcDir)
}

async function waitFor (fn, que, timeoutMs = 8000) {
  const t = Date.now() + timeoutMs
  while (Date.now() < t) {
    if (await fn()) return true
    await new Promise((r) => setTimeout(r, 100))
  }
  throw new Error('se agotó la espera de ' + que)
}

test('por aparato: se SUMAN a las del scope y le ganan al coincidir', async () => {
  // El caso real: dos máquinas sirviendo el mismo namespace. La llave de la API es una
  // sola (va en el scope) y el puerto es de cada una (va en el aparato). Si se llaman
  // igual, manda la del aparato: lo específico gana, como un `.env` de máquina sobre el
  // general.
  const { readServiceIdentity } = await import('../lib/src/service.js')
  const me = readServiceIdentity(svcDir).device.publickey

  await vault.setDeviceSecret(me, 'PORT', '8443')
  await vault.setDeviceSecret(me, 'TURN_KEY_ID', 'la-de-esta-maquina')

  const secrets = await fetchSecretsFrom(svcDir)
  assert.equal(secrets.PORT, '8443', 'lo suyo llega')
  assert.equal(secrets.TURN_KEY_ID, 'la-de-esta-maquina', 'y le gana a la del scope')
  assert.equal(secrets.TURN_KEY_API_TOKEN, 'rotada-2', 'lo demás del scope sigue llegando')

  // La lista da NOMBRES y quién es cada aparato; valores, ninguno.
  const dev = await vault.listDeviceSecrets()
  const row = dev.find((x) => x.pub === me)
  assert.deepEqual(row.keys.map((k) => k.key).sort(), ['PORT', 'TURN_KEY_ID'])
  assert.ok(row.keys.every((k) => k.public === false), 'nacen privadas')
  assert.equal(row.cn, 'proxy', 'se dice de qué servicio es, que es lo que decide qué ns lee')
  assert.ok(!JSON.stringify(dev).includes('la-de-esta-maquina'), 'nunca viajan los valores')

  // Y quitarla devuelve la del scope: el cajón de abajo nunca se tocó.
  await vault.deleteDeviceSecret(me, 'TURN_KEY_ID')
  assert.equal((await fetchSecretsFrom(svcDir)).TURN_KEY_ID, 'rotada-1')
})

test('las variables de un aparato solo se le ponen a un SERVICIO', async () => {
  // A un teléfono no se le pueden poner: no existe forma de que las lea (no pide bundle),
  // así que aceptarlas sería guardar configuración muerta donde nadie la va a buscar.
  const { makeDeviceKey } = await import('@dotrino/identity/capabilities')
  const stranger = await makeDeviceKey({ label: 'ajeno' })
  await assert.rejects(
    vault.setDeviceSecret(stranger.publickey, 'PORT', '1'),
    /not a member/
  )
  await assert.rejects(
    vault.setDeviceSecret(vault.identity.me.publickey, 'PORT', '1'),
    /not a service/
  )
})

test('la bóveda avisa a ESE aparato cuando cambia una variable suya', async () => {
  const { watchSecretsChanges, readServiceIdentity } = await import('../lib/src/service.js')
  const me = readServiceIdentity(svcDir).device.publickey
  const notices = []
  const w = await watchSecretsChanges({
    dir: svcDir, ns: 'proxy', graceMs: 0, minIntervalMs: 0, jitterMs: 0,
    onChange: (i) => notices.push(i)
  })
  try {
    await new Promise((r) => setTimeout(r, 4000)) // dejar pasar avisos en vuelo de otras pruebas
    notices.length = 0
    await vault.setDeviceSecret(me, 'PORT', '9443')
    await waitFor(() => notices.length > 0, 'el aviso de cambio del aparato')
    assert.equal(notices[0].ns, 'proxy', 'el aviso dice el namespace, que es lo que el agente sabe releer')
  } finally { w.stop() }
})

test('el aviso que NO llegó no deja al agente con la configuración vieja: al conectar compara', async () => {
  // El caso que rompía: el agente sigue vivo pero incomunicado (se cayó el proxio, se
  // fue la red). La bóveda manda el aviso, nadie lo recoge y queda en la cola; si el
  // corte pasa de cinco minutos, al volver lo tira la ventana de frescura, y si pasa de
  // 24 h ni llega. Antes ahí se acababa la historia: al reconectar el agente solo volvía
  // a ESCUCHAR, nunca preguntaba, y se quedaba con la configuración vieja para siempre
  // mientras el log decía «ignorado» como si estuviera todo bien.
  //
  // Se reproduce sin tocar la red: se le dice al vigía qué configuración tiene en uso
  // (`applied`) y se cambia el secreto ANTES de que exista — o sea, el aviso salió
  // cuando no había nadie escuchando, que es exactamente lo que pasa estando caído.
  const { watchSecretsChanges } = await import('../lib/src/service.js')
  const running = await fetchSecretsFrom(svcDir)

  await vault.setSecret('proxy', 'TURN_KEY_ID', 'rotada-mientras-no-miraba')
  await new Promise((r) => setTimeout(r, 600))   // el aviso sale y se pierde: no hay vigía

  const changes = []
  const w = await watchSecretsChanges({
    dir: svcDir, ns: 'proxy', applied: running, reconcileMinMs: 0,
    graceMs: 0, minIntervalMs: 999999, jitterMs: 0,
    onChange: (i) => changes.push(i)
  })
  try {
    await waitFor(() => changes.length > 0, 'la comparación al conectar')
    assert.equal(changes[0].via, 'reconcile', 'no se enteró por un aviso: se enteró preguntando')
    assert.equal(changes[0].ns, 'proxy')
    // Y no se repite: lo que encontró pasa a ser la referencia.
    assert.equal(await w.reconcile(), false, 'comparar otra vez no vuelve a disparar')
  } finally { w.stop() }
})

test('si la configuración es la misma, comparar no reinicia a nadie', async () => {
  // La otra mitad, y la que evita convertir el arreglo en un reinicio por reconexión:
  // el orden de las claves no cuenta (el bundle se arma mezclando dos cajones) y una
  // visibilidad no cambia lo que el servicio lee.
  const { watchSecretsChanges, readServiceIdentity } = await import('../lib/src/service.js')
  const me = readServiceIdentity(svcDir).device.publickey
  await vault.setSecret('proxy', 'TURN_URL', 'turn:x', true)   // pública, para poder taparla
  await new Promise((r) => setTimeout(r, 1500))   // que su aviso llegue ANTES de empezar a contar
  const changes = []
  const w = await watchSecretsChanges({
    dir: svcDir, ns: 'proxy', applied: await fetchSecretsFrom(svcDir), reconcileMinMs: 0,
    graceMs: 0, minIntervalMs: 999999, jitterMs: 0,
    onChange: (i) => changes.push(i)
  })
  try {
    await new Promise((r) => setTimeout(r, 800))   // que termine la comparación del arranque
    assert.equal(await w.reconcile(), false, 'nada cambió: nadie se muere')
    // Una pública que se tapa (la única dirección que existe): mismo valor, otro sobre.
    await vault.setSecretVisibility('proxy', 'TURN_URL', false)
    assert.equal(await w.reconcile(), false, 'cambiar quién ve el valor no es cambiar el valor')
    await new Promise((r) => setTimeout(r, 600))
    assert.equal(changes.length, 0, JSON.stringify(changes))

    // Y con un cambio de verdad sí, aunque sea del cajón del aparato.
    await vault.setDeviceSecret(me, 'PORT', '9999')
    assert.equal(await w.reconcile(), true)
  } finally {
    w.stop()
    await vault.deleteSecret('proxy', 'TURN_URL')
  }
})

test('el proxio arranca SIN variables y las recibe después: eso no es un cambio', async () => {
  // El camino exacto del proxio, que es el único que no espera al vault: sirve con su
  // `.env`, recibe el bundle tarde y lo aplica con `applyEnv`. Si la comparación tomara
  // ese primer bundle por «configuración distinta», el proxio se reiniciaría en cada
  // arranque — y como al volver haría lo mismo, sería un ciclo perpetuo.
  //
  // No puede pasar porque lo que se compara son dos bundles de la bóveda, nunca el
  // `.env` contra el bundle: la referencia es lo que el agente recibió. Aquí se
  // comprueba, no se argumenta.
  const { enrollService, waitForSecrets } = await import('../lib/src/service.js')
  const { encodeInvite } = await import('../lib/src/invite.js')
  const { applyEnv, watchEnv } = await import('../lib/src/env.js')
  // Servicio propio, como un proxio recién arrancado: los otros tests dejan avisos
  // encolados en el proxio para la llave que comparten (24 h de cola), y se drenarían
  // aquí sin tener nada que ver con lo que se está probando.
  const ns = 'proxio'
  const dir = tmp('svc-proxio-')
  await vault.setSecret(ns, 'RELAY_URL', 'wss://uno.example')
  // La configuración se deja puesta ANTES de que el servicio exista, y se espera a que
  // pase la ventana de agrupado: así ese primer `set` no le deja un aviso en la cola
  // (cuando sale, no hay a quién mandárselo). Es el orden real —primero se configura el
  // servicio, después se enrola— y aquí además evita medir el eco de la preparación.
  await new Promise((r) => setTimeout(r, 600))
  const { qr } = await vault.startPairing({ scope: [`vault:secrets:${ns}`], label: 'service:' + ns, ttlMs: 60000 })
  await enrolar({
    qr: encodeInvite(qr), ns, dir
  })

  const changes = []
  const secrets = await waitForSecrets({ dir, ns })
  applyEnv(secrets)                                    // …y el proxio ya estaba sirviendo
  const w = await watchEnv({
    ns, dir, quiet: true, reconcileMinMs: 0,
    graceMs: 0, minIntervalMs: 999999, jitterMs: 0,
    onUpdate: (i) => changes.push(i)                   // sin esto, `watchEnv` mataría el test
  })
  try {
    await new Promise((r) => setTimeout(r, 1200))
    assert.deepEqual(changes, [], 'recibir la configuración por primera vez no reinicia a nadie')
    assert.equal(await w.reconcile(), false, 'ni a la segunda, ni a la tercera')
    // Y `applied` no hace falta cablearlo: `watchEnv` toma como referencia lo último que
    // pasó por `applyEnv`, así que cualquier agente queda cubierto sin tocar su código.
    await vault.setSecret(ns, 'RELAY_URL', 'wss://dos.example')
    assert.equal(await w.reconcile(), true, 'un cambio de verdad sí')
  } finally { w.stop() }
})

test('la comparación no puede volverse un ciclo de reinicios: durante la gracia se APLAZA', async () => {
  // El cinturón. Si algo hiciera que la comparación encontrara siempre una diferencia,
  // sin este tope el proceso saldría a los dos segundos de arrancar, una y otra vez.
  // Con él, como mucho una vez por gracia de arranque — y lo importante: el aviso que
  // cae dentro de la gracia se APLAZA, no se descarta. Descartarlo era justo el defecto
  // que todo esto vino a cerrar.
  const { watchSecretsChanges } = await import('../lib/src/service.js')
  const running = await fetchSecretsFrom(svcDir)
  await vault.setSecret('proxy', 'TURN_KEY_ID', 'rotada-durante-la-gracia')
  await new Promise((r) => setTimeout(r, 600))

  const changes = []
  const w = await watchSecretsChanges({
    dir: svcDir, ns: 'proxy', applied: running, reconcileMinMs: 0,
    graceMs: 2500, minIntervalMs: 999999, jitterMs: 0,
    onChange: (i) => changes.push(i)
  })
  try {
    await new Promise((r) => setTimeout(r, 1200))
    assert.deepEqual(changes, [], 'recién arrancado no se reinicia por comparación')
    await waitFor(() => changes.length > 0, 'la comparación aplazada hasta el fin de la gracia')
    assert.equal(changes[0].via, 'reconcile', 'y cuando llega, llega entera')
  } finally { w.stop() }
})

test('quitar el aparato se lleva sus variables', async () => {
  // Si se quedaran, serían configuración de una llave que ya no entra — y volverían a la
  // vida el día que se enrole otro aparato con esa misma llave.
  const { enrollService, readServiceIdentity } = await import('../lib/src/service.js')
  const { encodeInvite } = await import('../lib/src/invite.js')
  const dir = tmp('svc-fugaz-')
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:fugaz'], label: 'servicio:fugaz', ttlMs: 60000 })
  await enrolar({
    qr: encodeInvite(qr), ns: 'fugaz', dir
  })
  const pub = readServiceIdentity(dir).device.publickey
  await vault.setDeviceSecret(pub, 'PORT', '1234')
  assert.ok((await vault.listDeviceSecrets()).some((x) => x.pub === pub))

  await vault.revokeDevice({ sub: pub })
  assert.ok(!(await vault.listDeviceSecrets()).some((x) => x.pub === pub), 'se fueron con él')
})

test('la consola remota ve NOMBRES y visibilidad, y ningún valor — tampoco el de una pública', async () => {
  // CAMBIÓ LA REGLA (dueño, 2026-09-02). Antes cruzaba el valor de las marcadas como
  // mostrables; ahora no cruza ninguno, porque «pública» dejó de significar «en claro»:
  // dice a quién se le despacha SIN APROBACIÓN, y se guarda sellada como cualquier otra.
  //
  // Lo que la consola sigue viendo es lo que necesita para administrar: qué hay y de qué
  // tipo. Ver un valor exige poder abrirlo, que es otra cosa y tiene su propio camino.
  await vault.setSecret('web', 'PUBLIC_URL', 'https://ejemplo.com', true)
  await vault.setSecret('web', 'API_KEY', 'sk-esta-no-sale')

  const { enc } = await vault.vars.list({ by: 'TEST' })
  const payload = JSON.parse(await vault.identity.openContent(enc))
  const web = payload.ns.web

  const pub = web.find((x) => x.key === 'PUBLIC_URL')
  assert.equal(pub.public, true, 'se sabe que es pública…')
  assert.ok(!('value' in pub), '…pero su valor tampoco sale')
  const priv = web.find((x) => x.key === 'API_KEY')
  assert.equal(priv.public, false, 'y de la privada, igual: que existe y que es privada')
  assert.ok(!('value' in priv))
  assert.ok(!JSON.stringify(payload).includes('sk-esta-no-sale'))
  assert.ok(!JSON.stringify(payload).includes('https://ejemplo.com'), 'ningún valor cruza')
})

test('la consola remota CREA variables (scope nuevo o aparato) y rota las privadas a ciegas', async () => {
  const { readServiceIdentity, } = await import('../lib/src/service.js')
  const { buildSealedVar, authorFromDeviceKey } = await import('../lib/src/admin.js')
  const { makeDeviceKey } = await import('@dotrino/identity/capabilities')
  const me = readServiceIdentity(svcDir).device.publickey

  // Quien administra: un aparato del acta, que es quien FIRMA cada sobre.
  const consola = await makeDeviceKey()
  await vault.identity.admitMember({ pub: consola.publickey, label: 'consola', caps: ['sign', 'admin', 'store', 'read'] })
  /** El sobre ya hecho, como lo manda la consola: la bóveda no lo abre. */
  const sobre = async (owner, key, value) => buildSealedVar({
    recipients: await vault.vars.recipients(owner.startsWith('ns:') ? { ns: owner.slice(3) } : { pub: owner.slice(4) }),
    owner, key, value, author: authorFromDeviceKey(consola)
  })
  const poner = async (dest, key, value, isPublic) => vault.vars.set({
    ...dest, key, public: isPublic,
    sealed: await sobre(dest.ns ? `ns:${dest.ns}` : `dev:${dest.pub}`, key, value),
    caller: consola.publickey
  })

  // Un scope que no existía: crear es parte de lo que se delega.
  await poner({ ns: 'nuevo' }, 'API_KEY', 'v1', false)
  assert.deepEqual(vault.listSecrets().nuevo, [{ key: 'API_KEY', public: false }])

  // Rotar una privada SIN haberla podido leer: es justo para lo que sirve.
  await poner({ ns: 'web' }, 'API_KEY', 'sk-rotada')
  assert.equal((await vault.openSecrets('web')).API_KEY, 'sk-rotada')
  assert.equal(vault.listSecrets().web.find((x) => x.key === 'API_KEY').public, false,
    'y rotarla no la vuelve visible por accidente')

  // Y también en el cajón de un aparato.
  await poner({ pub: me }, 'PUBLIC_URL', 'https://uno.example', true)
  assert.equal((await fetchSecretsFrom(svcDir)).PUBLIC_URL, 'https://uno.example')

  // SIN SOBRE NO HAY ESCRITURA, y ya no hay camino viejo al que caer.
  await assert.rejects(vault.vars.set({ ns: 'web', key: 'API_KEY' }), /already sealed|sealed/)
})

test('el scope corta el acceso a otro namespace', async () => {
  await vault.setSecret('geo', 'DB_PASSWORD', 'nope')
  await assert.rejects(
    fetchNsWithSavedCert('geo'),
    /unauthorized: scope/
  )
})

test('un cert revocado deja de poder leer', async () => {
  // Se revoca EL PAPEL QUE EL SERVICIO TIENE EN LA MANO, no «el último emitido».
  //
  // Eso valía cuando renovar retiraba el anterior —un aparato, un papel—, y eso se quitó:
  // retirarlo al emitir convertía cualquier renovación que fallara después en una expulsión
  // permanente (le pasó a dos servicios en la migración del VPS). Ahora pueden convivir
  // varios del mismo aparato, así que «el último» ya no identifica a nadie.
  // CON SU PROPIO DIRECTORIO, no el compartido: revocar el papel que usa `svcDir` deja sin
  // credencial a todos los tests que vienen después, y el fallo aparece lejos de aquí.
  const { readServiceIdentity, fetchSecrets } = await import('../lib/src/service.js')
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:revocado'], label: 'service:revocado', ttlMs: 60_000 })
  const dir = tmp('svc-revocado-')
  await enrolar({ qr, ns: 'revocado', dir })
  const mio = readServiceIdentity(dir)
  assert.ok(mio?.cert?.nonce, 'el servicio tiene su papel guardado')
  assert.deepEqual(await fetchSecrets({ dir }), {}, 'antes de revocar, entra')

  await vault.revokeDevice(mio.cert.nonce)
  await assert.rejects(fetchSecrets({ dir }), /unauthorized: revoked/)
})

/**
 * LA PROMESA DE CARGAR EN GRUPO: seis variables, UN aviso.
 *
 * Guardadas de una en una son seis cambios de configuración, y el servicio obedece el
 * primero —sale y lo levanta su supervisor— arrancando con lo que hubiera puesto en ese
 * momento, mientras quien administra sigue escribiendo. Este test cuenta los avisos que
 * llegan al servicio de verdad, por el proxy de verdad, que es donde eso se nota.
 */
test('cargar varias de una vez avisa UNA sola vez (y una a una, una por variable)', async () => {
  const { enrollService, watchSecretsChanges } = await import('../lib/src/service.js')
  const { encodeInvite } = await import('../lib/src/invite.js')
  // Servicio propio: este test no puede depender de en qué estado dejaron los otros al
  // que comparten (uno de ellos le revoca el certificado).
  const ns = 'lote'
  const svcDir = tmp('svc-lote-')
  await vault.setSecret(ns, 'YA_ESTABA', '0')
  const { qr } = await vault.startPairing({ scope: [`vault:secrets:${ns}`], label: 'service:' + ns, ttlMs: 60000 })
  await enrolar({
    qr: encodeInvite(qr), ns, dir: svcDir
  })

  const notices = []
  // Sin gracia ni mínimo entre avisos: aquí se cuenta lo que MANDA la bóveda, no los
  // frenos del agente (que tienen sus propias razones y su propia prueba).
  const w = await watchSecretsChanges({
    dir: svcDir, ns, graceMs: 0, minIntervalMs: 0, jitterMs: 0, onChange: (i) => notices.push(i)
  })
  const wait = (ms) => new Promise((r) => setTimeout(r, ms))

  try {
    // Que el vigilante ASIENTE antes de medir: al conectar hace su propia comparación,
    // y contarla aquí sería contar el arranque, no el lote. Antes no hacía falta por
    // puro azar de tiempos — el enrolamiento era más rápido que la ventana de agrupado.
    await wait(400)
    notices.length = 0
    await vault.applySecrets(ns, [
      { op: 'set', key: 'LOTE_UNO', value: '1' },
      { op: 'set', key: 'LOTE_DOS', value: '2' },
      { op: 'set', key: 'LOTE_TRES', value: '3' }
    ])
    await wait(600)
    assert.equal(notices.length, 1, 'tres variables juntas son UN cambio de configuración')
    const read = await fetchSecretsFrom(svcDir)
    assert.equal(read.LOTE_UNO, '1')
    assert.equal(read.LOTE_TRES, '3', 'y el servicio las lee todas, no las primeras')

    // El contraste, que es lo que justifica todo esto: sueltas y espaciadas, un aviso
    // por variable — o sea, un reinicio por variable.
    notices.length = 0
    for (const [k, v] of [['SUELTA_UNA', 'a'], ['SUELTA_DOS', 'b']]) {
      await vault.setSecret(ns, k, v)
      await wait(400)
    }
    assert.equal(notices.length, 2)
  } finally { w.stop() }
})

async function fetchSecretsFrom (dir) {
  const { fetchSecrets } = await import('../lib/src/service.js')
  return fetchSecrets({ dir })
}

async function fetchNsWithSavedCert (ns) {
  const { fetchSecrets, readServiceIdentity } = await import('../lib/src/service.js')
  const saved = readServiceIdentity(svcDir)
  return fetchSecrets({ ns, proxyUrl: saved.proxy, masterPubkey: saved.iss, device: saved.device, cert: saved.cert })
}

test('un agente VIEJO consigue su llave de cifrado SIN re-enrolarse', async () => {
  // El caso de produccion: los proxios se enrolaron antes de que las llaves de cifrado
  // existieran. Re-enrolarlos les cambiaria la pubkey y con ella perderian su cajon de
  // variables (va indexado por ella): arrancarian sin PROXY_PEERS ni PROXY_PUBLIC_URL y
  // la federacion se apagaria en silencio. Por eso la llave se registra en el sitio.
  const { enrollService, registerEncKey, fetchSecrets } = await import('../lib/src/service.js')
  const { encodeInvite } = await import('../lib/src/invite.js')
  const { readJson } = await import('../src/paths.js')
  const { atRestFor } = await import('../src/atrest.js')

  const ns = 'viejo'
  const svc = tmp('svc-viejo-')
  await vault.setSecret(ns, 'TURN_KEY', 'secreto-del-ns')
  const { qr } = await vault.startPairing({ scope: [`vault:secrets:${ns}`], label: 'proxy-viejo', ttlMs: 60000 })
  await enrolar({ qr: encodeInvite(qr), ns, dir: svc })

  // Rebajar la identidad a v1 (sin `enc`): asi estan hoy los dos proxios.
  const f = path.join(svc, 'service-identity.json')
  const antes = readJson(f, null, atRestFor(svc))
  const pubAntes = antes.device.publickey
  const sinEnc = { ...antes, v: 1 }; delete sinEnc.enc
  fs.writeFileSync(f, atRestFor(svc).encrypt(JSON.stringify(sinEnc)), { mode: 0o600 })
  assert.equal(readJson(f, null, atRestFor(svc)).enc, undefined, 'partimos sin llave de cifrado')

  // Lo que se corre en cada proxio.
  const r = await registerEncKey({ dir: svc })
  assert.equal(r.created, true, 'la genera')

  const ahora = readJson(f, null, atRestFor(svc))
  assert.equal(ahora.v, 2)
  assert.equal(ahora.device.publickey, pubAntes, 'la llave de FIRMA no se toca: de ella sale el nodeId')

  const m = (await vault.profileMembers()).members.find((x) => x.cn === ns)
  assert.equal(m.canSeal, true, 'y queda registrada en el acta')
  assert.equal(m.pub, pubAntes, 'sin cambiarle la pubkey, asi que conserva su cajon')

  assert.equal((await fetchSecrets({ dir: svc })).TURN_KEY, 'secreto-del-ns', 'y sigue leyendo')
})


test('la consola remota escribe SIN contrasena (§8.1)', async () => {
  // El cambio entero: sellar solo necesita las PUBLICAS de quien va a leer, asi que
  // guardar una variable nunca necesito la frase del perfil. Lo que la pedia era la copia
  // maestra de v4, y eso obligaba a teclear en un navegador la llave que abre TODOS los
  // cajones. Ya no viaja ninguna contraseña por este camino.
  const ns = 'consola'
  const { buildSealedVar, authorFromDeviceKey } = await import('../lib/src/admin.js')
  const { makeDeviceKey } = await import('@dotrino/identity/capabilities')
  const quien = await makeDeviceKey()
  await vault.identity.admitMember({ pub: quien.publickey, label: 'consola-many', caps: ['sign', 'admin'] })
  // CADA VARIABLE EN SU SOBRE, ya hecho (2026-09-02): la bóveda no abre ninguno.
  const recipients = await vault.vars.recipients({ ns })
  const r = await vault.vars.setMany({
    ns,
    items: [{
      key: 'DESDE_LA_CONSOLA',
      sealed: await buildSealedVar({ recipients, owner: `ns:${ns}`, key: 'DESDE_LA_CONSOLA', value: 'valor-remoto', author: authorFromDeviceKey(quien) })
    }],
    caller: quien.publickey,
    by: 'test'
  })
  assert.deepEqual(r.keys, ['DESDE_LA_CONSOLA'])

  // Y de verdad quedo guardada: sin el `await` que faltaba, la respuesta salia antes
  // de escribir y esto encontraba el cajon vacio.
  const lista = vault.listSecrets()[ns] || []
  assert.ok(lista.some((k) => k.key === 'DESDE_LA_CONSOLA'), 'la variable tiene que estar ya en el disco')
  assert.equal((await vault.openSecrets(ns)).DESDE_LA_CONSOLA, 'valor-remoto')
})


test('el servicio descifra AL VUELO: el valor no toca el disco en ningun momento', async () => {
  // Regla del ecosistema: un servicio no guarda sus variables, las abre cada vez. Lo
  // unico que persiste es su IDENTIDAD (llave del aparato + cert + llave de cifrado),
  // que es lo que se revoca si la maquina cae — no habia nada que robar.
  //
  // Esto ya era cierto, pero nada lo IMPEDIA: una cache «para no pedirlas en cada
  // arranque» es exactamente el atajo que alguien anadiria de buena fe, y desharia el
  // sellado entero. El test lo fija.
  const { enrollService, fetchSecrets, watchSecretsChanges } = await import('../lib/src/service.js')
  const { encodeInvite } = await import('../lib/src/invite.js')

  const ns = 'alvuelo'
  const svc = tmp('svc-alvuelo-')
  const VALOR = 'esto-no-puede-aparecer-en-ningun-archivo'
  await vault.setSecret(ns, 'SECRETO', VALOR)
  const { qr } = await vault.startPairing({ scope: [`vault:secrets:${ns}`], label: 'alvuelo', ttlMs: 60000 })
  await enrolar({ qr: encodeInvite(qr), ns, dir: svc })

  assert.equal((await fetchSecrets({ dir: svc })).SECRETO, VALOR, 'lo lee')

  // Y otra vez, y mirando cambios: los caminos por los que entraria una cache.
  assert.equal((await fetchSecrets({ dir: svc })).SECRETO, VALOR)
  const stop = await watchSecretsChanges({ dir: svc, onChange: () => {}, onError: () => {} }).catch(() => null)
  try { await new Promise((r) => setTimeout(r, 150)) } finally { try { await stop?.() } catch (_) {} }

  // TODO el arbol del servicio, byte a byte: ni en claro ni en base64.
  const enB64 = Buffer.from(VALOR, 'utf8').toString('base64')
  const vistos = []
  const andar = (d) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const f = path.join(d, e.name)
      if (e.isDirectory()) { andar(f); continue }
      const b = fs.readFileSync(f)
      vistos.push(e.name)
      assert.ok(!b.includes(VALOR), `${e.name} tiene el valor EN CLARO`)
      assert.ok(!b.includes(enB64), `${e.name} tiene el valor en base64`)
    }
  }
  andar(svc)
  // Lo unico que persiste: su identidad, la sal del cifrado en reposo que la protege, y
  // la HUELLA de la maquina que la escribio (`atrest.machine`) — que no guarda material,
  // solo un hash, y esta para que mover este directorio a otra maquina de un error claro
  // en vez de un fallo de AES. Aplica igual al servicio que a la boveda.
  assert.deepEqual(vistos.sort(), ['atrest.machine', 'atrest.salt', 'service-identity.json'],
    'un archivo NUEVO en el directorio del servicio es sospechoso: revisa que no sea una cache')
})


test('un sobre con la firma cambiada NO se abre: el agente comprueba la procedencia', async () => {
  // Envolver una llave solo necesita PUBLICAS, asi que cualquiera puede fabricar un sobre
  // valido para este servicio: abrirlo prueba que es para mi, no que lo escribio quien
  // debia. Lo que lo prueba es la firma de la llave de sellado que nombra el acta (§8.8).
  //
  // Se prueba sobre la comprobacion misma —no moviendo el archivo del disco— porque la
  // boveda sirve lo que tiene EN MEMORIA: tocarle el archivo por detras no simula a nadie.
  const { makeSealCheck } = await import('../lib/src/service.js')
  const { genesisActa, sealActa } = await import('@dotrino/identity/acta')
  const { signWithDevice } = await import('@dotrino/identity/capabilities')

  const par = async () => {
    const p = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
    return {
      pub: JSON.stringify(await crypto.subtle.exportKey('jwk', p.publicKey)),
      privateJwk: await crypto.subtle.exportKey('jwk', p.privateKey)
    }
  }
  const maestra = await par()
  const sello = await par()
  const acta = await sealActa({
    acta: genesisActa({ pub: maestra.pub, sealPub: sello.pub }), privateJwk: maestra.privateJwk
  })

  const e = { iv: 'aXY=', ct: 'Y3Q=' }
  const body = { owner: 'ns:x', key: 'TOKEN', gen: 1, iv: e.iv, ct: e.ct }
  const { signature } = await signWithDevice({ privateJwk: sello.privateJwk, publickey: sello.pub, data: body })

  const comprobar = await makeSealCheck(acta, maestra.pub, () => {})
  await comprobar('ns:x', 'TOKEN', 1, e, { seq: 1, sig: signature })   // la buena pasa

  await assert.rejects(
    () => comprobar('ns:x', 'TOKEN', 1, { iv: e.iv, ct: 'b3Ry' }, { seq: 1, sig: signature }),
    /signature does not check out/, 'un sobre cambiado con la firma vieja NO se usa')
  await assert.rejects(
    () => comprobar('ns:x', 'TOKEN', 1, e, { seq: 9, sig: signature }),
    /no sealing key/, 'ni uno que dice venir de un acta que no existe')

  // Y si el acta no la firmo la maestra que este agente conoce, no se finge que se
  // comprobo: se avisa y se sigue (no se puede establecer procedencia).
  const otra = await par()
  const ajena = await sealActa({ acta: genesisActa({ pub: otra.pub, sealPub: sello.pub }), privateJwk: otra.privateJwk })
  let aviso = ''
  const laxo = await makeSealCheck(ajena, maestra.pub, (m) => { aviso = m })
  await laxo('ns:x', 'TOKEN', 1, e, { seq: 1, sig: 'basura' })
  assert.match(aviso, /provenance NOT checked/)
})


test('quien administra NO puede ver un valor a distancia: la operacion no existe (2026-08-22)', async () => {
  // Lo que se quitó y no vuelve: `var.reveal` / `var.history` del protocolo de
  // administración. Un aparato que administra no tiene sobres de lo privado; ver, el
  // histórico y volver a una versión son de la bóveda en su máquina (CLI/TUI).
  assert.equal(vault.vars.reveal, undefined, 'no hay reveal para el admin')
  assert.equal(vault.vars.history, undefined, 'ni history')
  const { ADMIN_OPS } = await import('../lib/src/admin.js').catch(() => ({}))
  if (ADMIN_OPS) {
    assert.ok(!ADMIN_OPS.includes('var.reveal') && !ADMIN_OPS.includes('var.history'), 'y el protocolo tampoco las anuncia')
  }
})

/**
 * EL INVARIANTE del 2026-08-22: un cajón CON DUEÑO no se envuelve para quien administra.
 *
 * Es lo que hace que el token de R2 o las llaves de TURN no se puedan abrir desde un
 * navegador. Y se comprueba mirando el llavero, no la respuesta de una API: la protección
 * tenía que ser que la envoltura NO EXISTA, no que la bóveda se niegue a darla — un
 * envoltorio guardado se abre con el disco, sin preguntarle a nadie.
 */
test('un cajón con servicio dueño NO lleva envoltura de quien administra', async () => {
  const ns = 'condueno'
  const { qr } = await vault.startPairing({ scope: [`vault:secrets:${ns}`], label: 'service:' + ns, ttlMs: 60000 })
  const dir = tmp('svc-dueno-')
  const { enrollService } = await import('../lib/src/service.js')
  const svc = await enrolar({
    qr, ns, dir, label: 'service:' + ns
  })

  await vault.secrets.set(ns, 'TOKEN', 'el-secreto-del-servicio')

  const destinatarios = vault.secrets.recipientsIn(`ns:${ns}`)

  assert.ok(destinatarios.includes(svc.device.publickey), 'su servicio sí, faltaría más')
  assert.ok(destinatarios.includes('#recovery'), 'y la recuperación, que es lo que abre la frase')
  assert.equal(destinatarios.length, 2,
    'y NADIE más: ningún aparato que administre entra en un cajón que tiene dueño')
})

/**
 * LA DELEGACIÓN (§8.11): quien ENVUELVE la llave para un aparato nuevo es otro servicio del
 * mismo cajón — pero **se la entrega A LA BÓVEDA, que es quien la reparte**.
 *
 * Precisión del dueño (2026-09-01): «un servicio reparte la llave AL VAULT para que este la
 * reparta después, pero no se la entrega directo; si lo hace sin pasar por el vault está
 * mal». Y así está: la bóveda le PIDE el sobre al hermano (`REWRAP`), el hermano le contesta
 * A ELLA, y ella lo guarda (`putWrap`). El recién llegado no habla con nadie, y la bóveda
 * nunca ve la llave en claro —el sobre ya viene cerrado a la pública del destinatario—, que
 * es lo que permite que esto funcione con el perfil cerrado.
 *
 * Es el caso normal, no un rincón: cualquier segundo servicio de un `ns` entra después
 * de que sus variables ya estén escritas, y la bóveda no puede envolvérselas —hacerlo
 * exige abrir la llave, y abrirla pide la frase—. El hermano sí puede, y no gana nada:
 * ya podía leer eso.
 */
/**
 * La llave que sale de la frase del perfil. Aquí va fija porque lo que se prueba no es
 * derivarla —eso es de `profiles`— sino qué puede la bóveda con ella y sin ella.
 */
const PHRASE_KEY = new Uint8Array(32).fill(7)

test('un servicio le entrega la llave A LA BÓVEDA y ella se la reparte al que entra después', async () => {
  const ns = 'delegado'
  const { enrollService, fetchSecrets, watchSecretsChanges } = await import('../lib/src/service.js')

  const join = async (label) => {
    const { qr } = await vault.startPairing({ scope: [`vault:secrets:${ns}`], label, ttlMs: 60000 })
    const dir = tmp('svc-' + label + '-')
    const svc = await enrolar({
      qr, ns, dir, label
  })
    return { dir, ...svc }
  }
  const until = async (fn, ms = 8000) => {
    const end = Date.now() + ms
    while (Date.now() < end) { if (fn()) return true; await new Promise((r) => setTimeout(r, 100)) }
    return false
  }

  // CON FRASE. Sin ella la bóveda abre su propia llave de recuperación y se envuelve
  // sola al aprobar, así que la delegación no llegaría a hacer falta — y la prueba
  // pasaría sin probar nada. Con frase, la bóveda NO puede, que es el caso real.
  await vault.rekeySecrets(null, PHRASE_KEY)

  // El primero entra, se escribe la variable (su envoltura se hace al escribirla) y se
  // queda ESCUCHANDO: es lo que le permite atender la petición de reparto.
  const first = await join('service:first')
  await vault.secrets.set(ns, 'TOKEN', 'lo-que-hay-que-repartir')
  const watcher = await watchSecretsChanges({ dir: first.dir, ns, applied: null, log: () => {} })

  // El segundo entra DESPUÉS: la generación ya existe y no lo incluía. La bóveda no
  // puede envolvérsela —no tiene la frase—, así que se la pide a su hermano.
  const second = await join('service:second')
  const handed = await until(() => vault.secrets.recipientsIn(`ns:${ns}`).includes(second.device.publickey))
  assert.ok(handed, 'al enrolarse, su hermano le reparte la llave sin que nadie teclee la frase')

  // Y la prueba de que la envoltura sirve de verdad: el segundo lee el valor.
  assert.equal((await fetchSecrets({ dir: second.dir, ns })).TOKEN, 'lo-que-hay-que-repartir')

  const debts = await vault.incompleteMembers()
  assert.ok(!debts.some((d) => d.pub === second.device.publickey), 'y no queda como incompleto')
  // La deuda se CALCULA, así que saldada por el hermano deja de verse sin que nadie
  // tenga que borrar nada: la consola no puede seguir diciendo que «no leen sus variables».
  assert.ok(!(await vault.secretDebts())[`ns:${ns}`], 'y la deuda desaparece al repartirse la llave')

  watcher?.close?.()
})

test('sin nadie encendido que la reparta, la deuda se queda A LA VISTA', async () => {
  const ns = 'sinnadie'
  const { enrollService } = await import('../lib/src/service.js')
  const join = async (label) => {
    const { qr } = await vault.startPairing({ scope: [`vault:secrets:${ns}`], label, ttlMs: 60000 })
    const dir = tmp('svc-' + label + '-')
    return { dir, ...await enrolar({ qr, ns, dir, label }) }
  }

  const first = await join('service:one')          // enrolado, pero SIN escuchar
  await vault.secrets.set(ns, 'TOKEN', 'lo-de-este-cajon')
  const second = await join('service:two')

  assert.ok(!vault.secrets.recipientsIn(`ns:${ns}`).includes(second.device.publickey),
    'nadie pudo repartirle nada')
  const debts = await vault.incompleteMembers()
  const mine = debts.find((d) => d.pub === second.device.publickey)
  assert.ok(mine, 'y aparece como incompleto, que es lo que verá quien administre')
  assert.deepEqual(mine.owners[`ns:${ns}`], ['TOKEN'], 'diciendo exactamente qué no puede abrir')
  const owed = (await vault.secretDebts())[`ns:${ns}`]
  assert.equal(owed?.kind, 'rewrap', 'y la deuda SE VE calculada (es lo que lee la consola)')
  assert.deepEqual(owed.members, [{ pub: second.device.publickey, keys: ['TOKEN'] }], 'con quién y qué variable')

  // Y al abrir la bóveda se salda: es el otro camino, el de estar delante de la máquina.
  await vault.resealAll(PHRASE_KEY)
  assert.ok(vault.secrets.recipientsIn(`ns:${ns}`).includes(second.device.publickey),
    'abrir la bóveda rehace el llavero y lo deja al día')
  assert.ok(!(await vault.secretDebts())[`ns:${ns}`], 'y la deuda deja de verse: la consola deja de avisar')
  assert.equal(first.device.publickey && true, true)
})

test('aparato con approval: pide en cada petición, el aparato con `approve` firma, denegar corta', async () => {
  const { enrollWithVault, fetchSecrets, waitForSecrets } = await import('../lib/src/service.js')
  const { signWithDevice } = await import('@dotrino/identity/capabilities')
  const { requestRenew } = await import('@dotrino/identity/vault/remote.js')
  const { MSG } = await import('../src/protocol.js')
  const ttl = 30 * 24 * 60 * 60 * 1000

  // El agente (Claude): lee el cajón `claude`. La variable entra DESPUÉS de enrolarlo.
  const inv1 = await vault.startPairing({ scope: ['vault:sign', 'vault:secrets:claude'], label: 'claude', ttlMs: ttl })
  let permAgent = null
  const agent = await enrollWithVault({ qr: inv1.qr, label: 'claude', onCode: ({ code }) => { permAgent = aprobarYPermitir(code) } })
  await permAgent
  await vault.setSecret('claude', 'DEEPSEEK_API_KEY', 'sk-1')
  const args = { ns: 'claude', proxyUrl, masterPubkey: vault.master, device: agent.device, cert: agent.cert, enc: agent.enc }
  // CON el permiso `unattended` (se lo puso el arnés al aprobarlo): entrega directa.
  assert.equal(await vault.needsApproval(agent.device.publickey), false)
  assert.deepEqual(await fetchSecrets({ ...args, timeoutMs: 5000 }), { DEEPSEEK_API_KEY: 'sk-1' })

  // Se le QUITA, y con eso vuelve a pedir permiso. Antes esto era `setApproval` —una marca
  // local de la bóveda, invertida y fuera del acta—; ahora es un permiso más, así que se
  // quita como cualquier otro y lo respeta cualquier bóveda de la cuenta.
  const suyas = (await vault.identity.profileActa()).acta.members.find((m) => m.pub === agent.device.publickey).caps
  await vault.setCaps(agent.device.publickey, suyas.filter((c) => c !== 'unattended'))
  assert.equal(await vault.needsApproval(agent.device.publickey), true)

  // El teléfono: un aparato normal al que el dueño le concede `approve` a mano.
  const inv2 = await vault.startPairing({ scope: ['vault:sign'], label: 'phone', ttlMs: ttl })
  let permPhone = null
  const phone = await enrollWithVault({ qr: inv2.qr, label: 'phone', onCode: ({ code }) => { permPhone = aprobarYPermitir(code) } })
  await permPhone
  await vault.setCaps(phone.device.publickey, ['sign', 'approve'])
  const phoneCert = (await requestRenew({ master: vault.master, proxy: proxyUrl, device: phone.device, cert: phone.cert })).cert
  assert.ok(phoneCert.scope.includes('vault:approve'))

  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const rpc = async (data, cert, device) => {
    const c = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
    await c.connect()
    try {
      const signed = { ...data, publickey: device.publickey, ts: Date.now() }
      const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data: signed })
      const res = new Promise((resolve, reject) => {
        c.on('message', (_f, p) => { if (p?.type === MSG.SECRETS_RESULT) resolve(p); else if (p?.type === MSG.ERROR) reject(new Error(p.error)) })
        setTimeout(() => reject(new Error('timeout')), 8000)
      })
      c.sendByPubkey(vault.master, { type: MSG.SECRETS, data: signed, signature, cert })
      return await res
    } finally { c.close() }
  }
  const settle = () => new Promise((r) => setTimeout(r, 800))

  // 1) DENEGAR: error que NO se reintenta (ni con waitForSecrets).
  const w1 = fetchSecrets(args).catch((e) => e)
  await settle()
  const [p1] = vault.listApprovals()
  assert.equal(p1?.ns, 'claude'); assert.equal(p1.label, 'claude')
  assert.equal((await rpc({ op: 'deny', id: p1.id }, phoneCert, phone.device)).body.ok, true)
  assert.match((await w1).message, /unauthorized: denied/)
  const w2 = waitForSecrets({ ...args, retryMs: 100 }).catch((e) => e)
  await settle()
  const [p2] = vault.listApprovals()
  await rpc({ op: 'deny', id: p2.id }, phoneCert, phone.device)
  assert.match((await w2).message, /unauthorized: denied/)

  // 2) APROBAR: se lista, solo firma quien tiene `approve`, y se entrega.
  let pendingSeen = null
  const waiting = fetchSecrets({ ...args, onPending: (p) => { pendingSeen = p } })
  await settle()
  const list = vault.listApprovals()
  assert.equal(list.length, 1); assert.equal(pendingSeen?.id, list[0].id)
  assert.equal((await rpc({ op: 'approvals' }, phoneCert, phone.device)).body.items.length, 1)
  await assert.rejects(rpc({ op: 'approve', id: list[0].id }, agent.cert, agent.device), /unauthorized/)
  assert.equal((await rpc({ op: 'approve', id: list[0].id }, phoneCert, phone.device)).body.ok, true)
  assert.deepEqual(await waiting, { DEEPSEEK_API_KEY: 'sk-1' })
  assert.equal(vault.listApprovals().length, 0)

  // 3) SIN VENTANA: la siguiente petición vuelve a pedir (un servicio pide por arranque).
  const again = fetchSecrets(args).catch((e) => e)
  await settle()
  const [p3] = vault.listApprovals()
  assert.ok(p3, 'pide otra vez')
  await rpc({ op: 'approve', id: p3.id }, phoneCert, phone.device)
  assert.deepEqual(await again, { DEEPSEEK_API_KEY: 'sk-1' })

  // 4) Lo no atendido vence solo; y DEVOLVERLE el permiso vuelve a la entrega directa.
  const { createApprovals } = await import('../src/approvals.js')
  let t = 0
  const a = createApprovals({ now: () => t, pendingTtlMs: 10 })
  const r = a.request({ ns: 'x', device: 'd', deviceId: 'D', ek: 'e' })
  t = 11
  assert.deepEqual(a.sweep().map((x) => x.id), [r.id])

  // Antes esto era `setApproval(..., false)` sobre una lista local. Ahora es conceder el
  // permiso en el acta, y por eso se ve aquí lo que importa: surte efecto en la siguiente
  // petición, sin reiniciar nada ni renovar ningún papel.
  const caps = (await vault.identity.profileActa()).acta.members.find((m) => m.pub === agent.device.publickey).caps
  await vault.setCaps(agent.device.publickey, [...new Set([...caps, 'unattended'])])
  assert.equal(await vault.needsApproval(agent.device.publickey), false)
  assert.deepEqual(await fetchSecrets({ ...args, timeoutMs: 5000 }), { DEEPSEEK_API_KEY: 'sk-1' })
})

/**
 * QUITARLE EL PERMISO SURTE EFECTO YA — TAMBIÉN EN `enckey`.
 *
 * `handleEncKey` no le preguntaba al acta, solo al certificado. Y no es un mostrador
 * inocente: acto seguido le ENVUELVE al aparato la llave de su cajón (`spreadKey`). O sea
 * que a un servicio al que el dueño ya le había quitado el cajón se le seguía entregando
 * la llave, hasta 30 días — lo que dure el papel. Es el mismo fallo que se cerró en
 * `handleSign`, escondido en otro sitio.
 *
 * Se prueban los DOS mostradores: el que sirve el cajón (que ya miraba, pero con un
 * repliegue que decía «sin acta, pasa») y el que registra la llave (que no miraba).
 */
test('a un servicio al que el acta ya no reconoce: ni le sirven el cajón ni le registran la llave', async () => {
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:sonda'], label: 'service:sonda', ttlMs: 60_000 })
  const dir = tmp('svc-sonda-')
  const { enrollService, fetchSecrets, registerEncKey } = await import('../lib/src/service.js')
  const { device, cert } = await enrolar({
    qr, ns: 'sonda', dir
  })
  // EL PAPEL ORIGINAL, guardado aparte: es el que dice `vault:secrets:sonda`. Con él en la
  // mano y el acta en contra se prueba justo el hueco que había.
  const conElCajon = { ns: 'sonda', proxyUrl, masterPubkey: vault.master, device, cert }

  assert.deepEqual(await fetchSecrets({ dir }), {}, 'mientras el acta lo reconoce, se lo sirven')
  await registerEncKey({ dir, ...conElCajon })

  // El dueño le quita EL CAJÓN en el acta y le deja `firma`: sigue siendo miembro y su papel
  // sigue vivo diciendo `vault:secrets:sonda`. Dejarlo sin ningún permiso lo echaría del acta
  // y entonces lo pararía la revocación, que es otro camino.
  await vault.setCaps(device.publickey, ['sign'])

  // `enckey` con el papel viejo: la firma vale, el papel dice el cajón… y el acta no. Este
  // mostrador NO preguntaba, y acto seguido le ENVUELVE la llave del cajón (`spreadKey`).
  // Se exige el motivo EXACTO: «revoked» también contiene `unauthorized`, y el test pasaría
  // sin haber probado nada del acta.
  await assert.rejects(() => registerEncKey({ dir, ...conElCajon }), /cn —/,
    'registrar la llave tiene que mirar el acta, que era por donde se colaba')

  // Y servir el cajón tampoco. Aquí ni siquiera llega a preguntarse por el `cn`: al ver que
  // el acta cambió, el servicio pide papel nuevo y el que le dan ya no trae el cajón.
  await assert.rejects(() => fetchSecrets({ dir }), /scope|cn —/, 'servir el cajón dice que no')
})

/**
 * LA LLAVE DE COMUNICACIÓN ENTRA EN EL ACTA SOLO CON EL PERFIL ABIERTO.
 *
 * Esto se coló EN PRODUCCIÓN y por eso queda clavado aquí. El guardián preguntaba
 * `identity.masterLocked`, y en la primera arrancada tras actualizar la maestra todavía está
 * guardada en claro —se sella al abrir el perfil—, así que `masterLocked` es `false` aunque
 * el perfil esté CERRADO. La bóveda del VPS se admitió sola y selló un acta nueva (#76 → #77)
 * con el candado echado, rotando de paso la llave de sellado sin que nadie lo pidiera.
 *
 * Son dos preguntas distintas y hay que hacer las dos: «¿tengo con qué firmar?» y «¿me dejan?».
 */
test('con el perfil CERRADO la bóveda no se mete sola en su propia acta', async () => {
  const { startVault } = await import('../src/vault.js')
  const dir = tmp('vault-cerrada-')
  const cerrada = await startVault({ dir, proxyUrl, log: () => {}, isLocked: () => true })
  try {
    const acta = (await cerrada.identity.profileActa()).acta
    assert.equal(acta.seq, 1, 'no se selló ninguna acta nueva al arrancar')
    assert.equal(acta.members.length, 1, 'y no se metió a sí misma como miembro')
  } finally { cerrada.close() }

  // Abierta sí: entra, y con `cn` de servicio — habla por la bóveda, no firma por la persona.
  const abierta = await startVault({ dir, proxyUrl, log: () => {}, isLocked: () => false })
  try {
    const suya = (await abierta.identity.profileActa()).acta.members.find((m) => m.cn === 'vault')
    assert.ok(suya, 'abierta, la llave de comunicación entra en el acta')
    assert.deepEqual(suya.caps, ['sign'])
  } finally { abierta.close() }
})

/**
 * UN SERVICIO PREGUNTA POR SUS REVOCACIONES SIN VER TU INVENTARIO.
 *
 * `vault.devices` responde dos cosas distintas según quién pregunte, y esto lo fija porque
 * lo rompí en producción: le exigí `lee` al mostrador entero y dejé ciegos a los servicios
 * —quedaron dos `rejected devices/acta` en la bitácora del VPS antes de que lo viera—.
 * Un servicio necesita saber si le revocaron el papel y cuál es el acta vigente; eso no es
 * tu inventario. La lista de aparatos, que sí lo es, sigue pidiendo `lee`.
 */
test('un servicio ve sus revocaciones y el acta, pero NO la lista de aparatos', async () => {
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:mirador'], label: 'service:mirador', ttlMs: 60_000 })
  const dir = tmp('svc-mirador-')
  const { enrollService } = await import('../lib/src/service.js')
  const { device, cert } = await enrolar({
    qr, ns: 'mirador', dir
  })

  const { WebSocketProxyClient } = await import('@dotrino/proxy-client')
  const client = new WebSocketProxyClient({ url: proxyUrl, enableWebRTC: false, autoReconnect: false })
  await client.connect()
  try {
    const data = { op: 'devices', publickey: device.publickey, ts: Date.now() }
    const { signature } = await signWithDevice({ privateJwk: device.privateJwk, data })
    const res = await new Promise((resolve, reject) => {
      const off = client.on('message', (_f, p) => {
        if (p?.type === 'vault.devices.result') { off(); resolve(p) }
        else if (p?.type === 'vault.error') { off(); reject(new Error(p.error)) }
      })
      setTimeout(() => { off(); reject(new Error('timeout')) }, 10000)
      client.sendByPubkey(vault.master, { type: 'vault.devices', data, signature, cert })
    })
    assert.ok(Array.isArray(res.revoked), 'se entera de las revocaciones')
    assert.ok(res.acta?.seq, 'y del acta vigente, que es con lo que juzga a quien le hable')
    assert.deepEqual(res.devices, [], 'pero tu inventario no lo ve: no es asunto suyo')
  } finally { client.close() }
})

// AQUÍ IRÍA el test de «un papel del modelo viejo pide uno nuevo en cuanto habla», y no
// está porque no se puede escribir honestamente desde aquí: forjar uno quitándole el `seq`
// rompe su firma (el cuerpo canónico de un papel viejo lleva `exp`, y se firmó sobre ese),
// y esta bóveda ya no sabe emitir de los viejos. Se comprobó contra los diez papeles de
// verdad que hay en el VPS, mirando la bitácora: `renew` seguido de `secrets` servido.

/**
 * UNA RESPUESTA QUE NO CABE NO MATA LA CONEXIÓN.
 *
 * El proxio corta los frames a 1 MB (`maxPayload`) y `ws` no «descarta» el que se pasa:
 * CIERRA el socket con un 1009. La bóveda se queda muda, sin un error en su log, y desde
 * fuera se ve igual que si estuviera apagada. Eso ya pasó y duró tres días.
 *
 * Antes se avisaba y se mandaba igual. Ahora se sustituye por un error, que sí cabe: una
 * bóveda que dice «no cabe» se arregla; una muda no se puede ni diagnosticar.
 */
test('una respuesta demasiado grande se cambia por un error, no revienta el socket', async () => {
  const { startVault } = await import('../src/vault.js')
  const dir = tmp('vault-frame-')
  const v = await startVault({ dir, proxyUrl, log: () => {} })
  try {
    const enviados = []
    const original = v.client.send.bind(v.client)
    v.client.send = (to, obj) => { enviados.push(obj); return original(to, obj) }

    // Se pide una respuesta imposible por el mismo camino que usa el mostrador.
    v.reply('token-de-prueba', { type: 'vault.devices.result', relleno: 'x'.repeat(900 * 1024) })

    assert.equal(enviados.length, 1, 'se contesta: callarse es el fallo que se está cerrando')
    assert.equal(enviados[0].type, 'vault.error', 'y lo que sale es un error, no el mensajón')
    assert.match(enviados[0].error, /reply too big/)
    assert.ok(Buffer.byteLength(JSON.stringify(enviados[0])) < 1024, 'que cabe de sobra')

    // Y lo que sí cabe pasa tal cual.
    v.reply('token-de-prueba', { type: 'vault.devices.result', devices: [] })
    assert.equal(enviados[1].type, 'vault.devices.result')
  } finally { v.close() }
})

/**
 * RECIBIR CLAVES PRIVADAS SIN APROBACIÓN ES UN PERMISO, Y EL DEFECTO ES PEDIRLA.
 *
 * Antes era al revés y vivía fuera del acta: una lista local de «estos SÍ piden permiso».
 * Así que un aparato nuevo nacía pudiendo llevarse las claves y nadie elegía eso — se
 * elegía por omisión, que es la peor forma de decidir algo así. Y al no estar en el acta
 * no se veía en la pantalla de permisos ni lo respetaba otra bóveda de la cuenta.
 *
 * Ahora se concede a propósito (`+desatendido`) y, si falta, se pide permiso.
 */
test('un servicio SIN el permiso espera aprobación; con él, se sirve solo', async () => {
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:vigilado'], label: 'service:vigilado', ttlMs: 60_000 })
  const dir = tmp('svc-vigilado-')
  const { enrollService, fetchSecrets } = await import('../lib/src/service.js')
  const { device } = await enrollService({
    qr, ns: 'vigilado', dir,
    // A propósito SIN el atajo: este test prueba justo que sin el permiso no se sirve.
    onCode: ({ code }) => { vault.approveDevice(code).catch((e) => { throw e }) }
  })

  // Recién enrolado NO tiene `unattended`: pedir sus claves se queda esperando a que
  // alguien con `aprueba` lo firme. Nadie lo tiene aquí, así que se agota — y eso es
  // exactamente lo que debe pasar.
  const pendiente = []
  await assert.rejects(
    () => fetchSecrets({ dir, timeoutMs: 3000, approvalTimeoutMs: 3000, onPending: (p) => pendiente.push(p) }),
    /approval|timeout/i,
    'sin el permiso no se entrega nada'
  )
  assert.equal(pendiente.length, 1, 'y se dice que está esperando, no se calla')
  assert.equal(pendiente[0].ns, 'vigilado')

  // Se le concede, y ya se sirve solo. El secreto se guarda DESPUÉS de que el aparato esté
  // dentro: un cajón escrito antes no tiene envoltura para quien llega luego, y el fallo
  // sería «no key to open», que no es lo que este test mira.
  await vault.setCaps(device.publickey, ['secrets', 'unattended'])
  await vault.setSecret('vigilado', 'TOKEN', 't-1')
  assert.deepEqual(await fetchSecrets({ dir }), { TOKEN: 't-1' }, 'con el permiso, sin preguntar a nadie')

  // Y quitárselo lo devuelve a pedir permiso, en el acto.
  await vault.setCaps(device.publickey, ['secrets'])
  await assert.rejects(() => fetchSecrets({ dir, timeoutMs: 3000, approvalTimeoutMs: 3000 }), /approval|timeout/i)
})

/**
 * LA COPIA DE RECUPERACIÓN SELLADA CON LA LLAVE DE LA MÁQUINA, EN UN PERFIL CON CONTRASEÑA.
 *
 * Cómo se llega ahí por un camino normal: escribir una variable NO pide la frase (§8.1), así
 * que si el cajón se estrena con el perfil CERRADO, `ensureRecovery` la sella con lo único
 * que hay a mano — la llave de la máquina. Después, abrir el perfil pasa la llave de la
 * CONTRASEÑA, que no abre ese sobre: «wrong password» en cada cajón, el llavero no se rehace
 * y los servicios se quedan sin poder leer nada. Para siempre, y sin que nadie lo dijera.
 *
 * Le pasó a un perfil real el 2026-09-01 y así se descubrió todo esto. Ahora el desbloqueo
 * lo migra: abre con la de la máquina y vuelve a cerrar con la frase.
 */
test('un cajón sellado con la llave de la máquina se migra a la frase al abrir', async () => {
  const ns = 'migrar'
  await vault.setSecret(ns, 'TOKEN', 'valor')

  // EL ESTADO SE MONTA AQUÍ, no se hereda. Un test anterior de este fichero deja la
  // recuperación bajo `PHRASE_KEY`, así que hay que devolverla a la llave de la MÁQUINA
  // —que es el estado que rompía— en vez de dar por hecho con qué está cerrada. Depender
  // del orden es cómo esta misma prueba pasaba sola y fallaba acompañada.
  try { await vault.rekeySecrets(PHRASE_KEY, null) } catch (_) { /* ya estaba con la de la máquina */ }

  const FRASE = new Uint8Array(32).fill(9)
  // Y ahora se abre con una frase que NUNCA selló nada: es el perfil al que le pusieron
  // contraseña después, sin rekey. Antes de la migración esto fallaba con «wrong password»
  // en cada cajón y `resealAll` no envolvía nada.
  const r = await vault.resealAll(FRASE)
  assert.equal(r.failed.length, 0, 'ningún cajón se queda sin reenvolver: ' + JSON.stringify(r.failed))
  assert.ok(r.drawers > 0, 'y se recorrieron cajones de verdad')

  // La migración se ACABA: a partir de ahora la copia va bajo la frase, y la llave de la
  // máquina ya no la abre. Que es más estricto que antes, no menos.
  const r2 = await vault.resealAll(FRASE)
  assert.equal(r2.failed.length, 0, 'y al segundo desbloqueo sigue funcionando, sin volver a migrar')
})

/**
 * SOLO PÚBLICAS: NI APROBACIÓN NI PRIVADAS.
 *
 * Pedido por el dueño (2026-09-01): «me gustaría que pudiera traer solamente públicas, eso
 * no necesitaría aprobación». Y es correcto: la aprobación existe para soltar CLAVES
 * PRIVADAS. Una pública está guardada en claro —eso es lo que significa marcarla— y ya la ve
 * cualquiera que administre, así que hacer sonar el teléfono para entregarla es molestar por
 * nada. Sirve para un arranque que solo necesita configuración y no debe despertar a nadie.
 *
 * Lo que se fija aquí es lo que hace peligroso el atajo: que el filtro lo haga LA BÓVEDA. Si
 * mandara todo y el cliente eligiera, pedir «solo públicas» sería exactamente la forma de
 * saltarse la aprobación y llevarse las privadas igual.
 */
test('--public: llega sin aprobación, y NO trae ninguna privada', async () => {
  const { encodeInvite } = await import('../lib/src/invite.js')
  const { fetchSecrets } = await import('../lib/src/service.js')
  const ns = 'mixto'
  const dir = tmp('svc-mixto-')

  // SE ENROLA PRIMERO, y después se escriben las variables. Desde 2026-09-02 una pública
  // también va en sobre, así que quien llega DESPUÉS de que se escriba necesita que se le
  // haga su envoltura — eso es otro camino (el del servicio que llega tarde) y tiene su
  // propio test. Aquí lo que se prueba es el despacho sin aprobación.
  //
  // Se enrola SIN `unattended`: sin ese permiso, cualquier petición normal se queda
  // esperando aprobación. Es lo que hace la prueba concluyente.
  const { qr } = await vault.startPairing({ scope: [`vault:secrets:${ns}`], label: 'service:' + ns, ttlMs: 60000 })
  const { enrollService } = await import('../lib/src/service.js')
  await enrollService({ qr: encodeInvite(qr), ns, dir, onCode: ({ code }) => vault.approveDevice(code) })
  // Su primera petición registra su llave de cifrado: hasta entonces no hay a dónde
  // envolver, y las variables escritas antes no serían suyas.
  await fetchSecrets({ dir, ns, publicOnly: true }).catch(() => null)

  await vault.setSecret(ns, 'PUBLIC_URL', 'https://ejemplo', true)
  await vault.setSecret(ns, 'API_TOKEN', 'secreto', false)

  // Nadie va a aprobar nada: si esto pidiera aprobación, se quedaría colgado.
  let pidioAprobacion = false
  const solo = await fetchSecrets({ dir, ns, publicOnly: true, onPending: () => { pidioAprobacion = true } })

  assert.equal(pidioAprobacion, false, 'no se pidió aprobación: no hay privadas de por medio')
  assert.equal(solo.PUBLIC_URL, 'https://ejemplo')
  assert.equal('API_TOKEN' in solo, false,
    'la PRIVADA no viaja — y la filtra la bóveda, no el cliente: si la mandara, «solo públicas» sería el atajo para saltarse la aprobación')

  // Y sin el atajo, lo de siempre: se pide aprobación (aquí nadie contesta, así que se
  // comprueba que la bóveda lo APUNTA, no que se resuelva).
  let pendiente = null
  // `approvalTimeoutMs` corto: aquí NADIE va a aprobar, y lo que se comprueba es que la
  // bóveda APUNTA el pedido — no que se resuelva. Sin el plazo, esto espera los 5 minutos
  // de verdad y el test se queda colgado.
  const normal = fetchSecrets({ dir, ns, approvalTimeoutMs: 1500, onPending: (p) => { pendiente = p } })
    .then(() => null, () => null)
  const hasta = Date.now() + 8000
  while (!pendiente && Date.now() < hasta) await new Promise((r) => setTimeout(r, 100))
  assert.ok(pendiente, 'la petición normal SÍ pasa por la aprobación')
  await normal
})

/**
 * ESCRIBIR SIN QUE LA BÓVEDA VEA EL VALOR, Y CON LA FIRMA DE SU AUTOR.
 *
 * Dos reglas del dueño (2026-09-01), que van juntas:
 *
 *   · «La bóveda cerrada no puede ver el valor; debe confiar en la firma del admin y en el
 *     contenido de esos sobres, y es la razón por la que al abrir la bóveda rehace los
 *     sobres: por si alguno tiene alguna incoherencia.»
 *   · «Los sobres deben traer información de quién los hizo… solo puede haber sobres
 *     firmados por miembros del acta», porque «un cn no puede poner un sobre faltante fuera
 *     de su cn».
 *
 * Antes escribir hacía un rodeo: la consola sellaba el valor AL PERFIL, la bóveda lo ABRÍA
 * para sacarlo en claro y lo volvía a cerrar. Ese descifrado era el ÚNICO motivo por el que
 * la llave de cifrado del perfil tenía que estar accesible con la bóveda cerrada — o sea, la
 * razón por la que una copia del disco abría todo lo dirigido al perfil.
 */
test('var.set con el sobre HECHO: la bóveda no lo abre, y exige la firma de su autor', async () => {
  const { buildSealedVar, authorFromDeviceKey } = await import('../lib/src/admin.js')
  const { makeDeviceKey } = await import('@dotrino/identity/capabilities')
  const ns = 'sinver'

  // El autor: un aparato del acta que administra.
  const yo = await makeDeviceKey()
  await vault.identity.admitMember({ pub: yo.publickey, label: 'consola', caps: ['sign', 'admin', 'store', 'read'] })
  const owner = `ns:${ns}`

  // 1. La BÓVEDA dice a quién hay que envolver (la lista sale del acta, la sabe ella).
  const recipients = await vault.vars.recipients({ ns })
  assert.ok(recipients.recoveryPub, 'y la de recuperación va incluida')

  // 2. El autor fabrica el sobre y lo firma. El valor no sale de aquí en claro.
  const sealed = await buildSealedVar({ recipients, owner, key: 'TOKEN', value: 'lo-que-no-ve', author: authorFromDeviceKey(yo) })
  await vault.vars.set({ ns, key: 'TOKEN', sealed, caller: yo.publickey, by: 'test' })

  // 3. Quedó guardado EXACTAMENTE lo que se mandó: nadie lo abrió para volver a cerrarlo.
  //
  //    Se comprueba sobre lo GUARDADO y no leyendo el valor, a propósito: leerlo pide la
  //    copia de recuperación, y de qué llave depende esa copia cambia según qué test de
  //    este fichero corrió antes — hacer depender esto del orden es lo que lo rompía. Y lo
  //    que se prueba aquí es justo que la bóveda NO abrió nada.
  const dentro = vault.listSecrets()[ns] || []
  assert.ok(dentro.some((k) => k.key === 'TOKEN'), 'la variable está guardada')
  assert.ok(vault.secretRecipients(owner).includes('#recovery'),
    'con la envoltura de recuperación, que es la que rehace todas las demás al abrir')
  assert.deepEqual(
    vault.secretRecipients(owner).filter((p) => p !== '#recovery').sort(),
    Object.keys(sealed.wraps).filter((p) => p !== '#recovery').sort(),
    'y las envolturas guardadas son EXACTAMENTE las que mandó el autor')

  // UN SOBRE SIN AUTOR NO ENTRA.
  const sinAutor = { ...sealed }; delete sinAutor.author
  await assert.rejects(vault.vars.set({ ns, key: 'OTRA', sealed: sinAutor, caller: yo.publickey }),
    /WHO made it/, 'tiene que decir quién lo hizo')

  // UNA FIRMA DE UNA LLAVE QUE EL ACTA NO NOMBRA, TAMPOCO.
  const extrano = await makeDeviceKey()
  const ajeno = await buildSealedVar({ recipients, owner, key: 'OTRA', value: 'x', author: authorFromDeviceKey(extrano) })
  await assert.rejects(vault.vars.set({ ns, key: 'OTRA', sealed: ajeno, caller: extrano.publickey }),
    /the record does not name/, 'un extraño no cuela un sobre aunque lo firme bien')

  // UN SERVICIO NO PISA LO QUE YA HAY, solo rellena lo que falta (dueño, 2026-09-01).
  // Misma regla que `putWrap`, y por lo mismo: reemplazar un sobre con uno basura dejaría
  // sin leer a otro miembro — denegación de servicio disfrazada de escritura.
  const servicio = await makeDeviceKey()
  await vault.identity.admitMember({ pub: servicio.publickey, label: 'svc', cn: ns, caps: ['secrets'] })
  const rec2 = await vault.vars.recipients({ ns })
  const suyo = await buildSealedVar({ recipients: rec2, owner, key: 'TOKEN', value: 'pisado', author: authorFromDeviceKey(servicio) })
  await assert.rejects(vault.vars.set({ ns, key: 'TOKEN', sealed: suyo, caller: servicio.publickey }),
    /cannot overwrite/, 'un servicio no reemplaza un sobre que ya existe')

  // Pero SÍ puede rellenar uno que falta en SU cajón.
  const nueva = await buildSealedVar({ recipients: rec2, owner, key: 'NUEVA', value: 'la-pone-el-servicio', author: authorFromDeviceKey(servicio) })
  await vault.vars.set({ ns, key: 'NUEVA', sealed: nueva, caller: servicio.publickey })
  assert.ok((vault.listSecrets()[ns] || []).some((k) => k.key === 'NUEVA'), 'sí puede rellenar la que falta')

  // Y no en el cajón de otro.
  const ajenoCajon = await buildSealedVar({
    recipients: await vault.vars.recipients({ ns: 'consola' }), owner: 'ns:consola', key: 'X', value: 'z', author: authorFromDeviceKey(servicio)
  })
  await assert.rejects(vault.vars.set({ ns: 'consola', key: 'X', sealed: ajenoCajon, caller: servicio.publickey }),
    /own drawer/, 'un cn no escribe fuera de su cn')

  // Y UNA FIRMA QUE NO CUADRA CON ESTE SOBRE: se firmó para OTRA clave del mismo cajón.
  const paraOtra = await buildSealedVar({ recipients, owner, key: 'DISTINTA', value: 'y', author: authorFromDeviceKey(yo) })
  await assert.rejects(
    vault.vars.set({ ns, key: 'TOKEN', sealed: { ...paraOtra, author: paraOtra.author }, caller: yo.publickey }),
    /does not verify/,
    'la firma lleva dentro el cajón y la clave: no se puede reusar en otro sitio')
})
