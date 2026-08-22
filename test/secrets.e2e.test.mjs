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

const require = createRequire(import.meta.url)
const proxyServerPath = path.join(path.dirname(fileURLToPath(import.meta.url)), '..', '..', 'dotrino-proxy', 'server.js')

const tmp = (name) => fs.mkdtempSync(path.join(os.tmpdir(), name))

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
  vault = await startVault({ dir: tmp('vault-e2e-'), proxyUrl, log: () => {} })
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
  const { device, cert } = await enrollService({
    qr, ns: 'proxy', dir: svcDir,
    onCode: ({ code }) => { vault.approveDevice(code).catch((e) => { throw e }) }
  })
  assert.ok(device?.publickey && cert?.sig)
  assert.deepEqual(cert.scope, ['vault:secrets:proxy'])
  assert.equal(readServiceIdentity(svcDir)?.ns, 'proxy')

  const secrets = await fetchSecrets({ dir: svcDir })
  assert.deepEqual(secrets, { TURN_KEY_ID: 'k-123', TURN_KEY_API_TOKEN: 't-456' })
})

test('la lista enseña el valor de las PÚBLICAS y tapa el de las privadas', async () => {
  // «Pública» quiere decir UNA cosa: que ese valor puede salir de esta máquina. Taparlo
  // justo aquí —en la lista que mira su dueño desde la terminal de la propia bóveda—
  // era lo único que la marca no significaba, y obligaba a abrir `secrets.json` a mano
  // para comprobar una URL. La privada sigue sin salir ni a esta lista.
  await vault.setSecret('escaparate', 'PUBLIC_URL', 'https://ejemplo.com', true)
  await vault.setSecret('escaparate', 'API_KEY', 's3cr3t')
  assert.deepEqual(vault.listSecrets().escaparate, [
    { key: 'PUBLIC_URL', public: true, value: 'https://ejemplo.com' },
    { key: 'API_KEY', public: false }
  ])

  // El cajón por aparato va por la misma regla, y por el mismo camino.
  const pub = 'PUB-DE-UN-APARATO'
  await vault.secrets.setDevice(pub, 'PORT', '8443', true)
  await vault.secrets.setDevice(pub, 'DB_PASSWORD', 'nope')
  const row = (await vault.listDeviceSecrets()).find((d) => d.pub === pub)
  assert.deepEqual(row.keys, [
    { key: 'PORT', public: true, value: '8443' },
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

    await enrollService({
      qr: comoLoDa(qr), ns, dir,                       // ← un STRING, como lo pega un humano
      onCode: ({ code }) => { vault.approveDevice(code).catch((e) => { throw e }) }
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
    return enrollService({
      qr: encodeInvite(qr), ns, dir, onReplace,
      onCode: ({ code }) => { vault.approveDevice(code).catch((e) => { throw e }) }
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
  const changes = []
  const w = await watchSecretsChanges({
    dir: svcDir, ns: 'proxy', applied: await fetchSecretsFrom(svcDir), reconcileMinMs: 0,
    graceMs: 0, minIntervalMs: 999999, jitterMs: 0,
    onChange: (i) => changes.push(i)
  })
  try {
    await new Promise((r) => setTimeout(r, 800))   // que termine la comparación del arranque
    assert.equal(await w.reconcile(), false, 'nada cambió: nadie se muere')
    await vault.setSecretVisibility('proxy', 'TURN_KEY_ID', true)
    assert.equal(await w.reconcile(), false, 'cambiar quién ve el valor no es cambiar el valor')
    await new Promise((r) => setTimeout(r, 600))
    assert.equal(changes.length, 0)

    // Y con un cambio de verdad sí, aunque sea del cajón del aparato.
    await vault.setDeviceSecret(me, 'PORT', '9999')
    assert.equal(await w.reconcile(), true)
  } finally {
    w.stop()
    await vault.setSecretVisibility('proxy', 'TURN_KEY_ID', false)
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
  await enrollService({
    qr: encodeInvite(qr), ns, dir,
    onCode: ({ code }) => { vault.approveDevice(code).catch((e) => { throw e }) }
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
  await enrollService({
    qr: encodeInvite(qr), ns: 'fugaz', dir,
    onCode: ({ code }) => { vault.approveDevice(code).catch((e) => { throw e }) }
  })
  const pub = readServiceIdentity(dir).device.publickey
  await vault.setDeviceSecret(pub, 'PORT', '1234')
  assert.ok((await vault.listDeviceSecrets()).some((x) => x.pub === pub))

  await vault.revokeDevice({ sub: pub })
  assert.ok(!(await vault.listDeviceSecrets()).some((x) => x.pub === pub), 'se fueron con él')
})

test('la consola remota ve el valor de una PÚBLICA y jamás el de una privada', async () => {
  // Es la frontera entera de `docs/consola-remota.md` para variables: lo que cruza no es
  // «los secretos», son los que su dueño marcó como mostrables.
  await vault.setSecret('web', 'PUBLIC_URL', 'https://ejemplo.com', true)
  await vault.setSecret('web', 'API_KEY', 'sk-esta-no-sale')

  const { enc } = await vault.vars.list({ by: 'TEST' })
  const payload = JSON.parse(await vault.identity.openContent(enc))
  const web = payload.ns.web

  assert.equal(web.find((x) => x.key === 'PUBLIC_URL').value, 'https://ejemplo.com')
  const priv = web.find((x) => x.key === 'API_KEY')
  assert.equal(priv.public, false, 'se sabe que existe y que es privada…')
  assert.ok(!('value' in priv), '…pero su valor no sale ni dentro del sobre')
  assert.ok(!JSON.stringify(payload).includes('sk-esta-no-sale'))
})

test('la consola remota CREA variables (scope nuevo o aparato) y rota las privadas a ciegas', async () => {
  const { readServiceIdentity } = await import('../lib/src/service.js')
  const me = readServiceIdentity(svcDir).device.publickey
  const sealed = (value) => vault.identity.sealContent(JSON.stringify({ value }))

  // Un scope que no existía: crear es parte de lo que se delega.
  await vault.vars.set({ ns: 'nuevo', key: 'API_KEY', enc: await sealed('v1'), public: false })
  assert.deepEqual(vault.listSecrets().nuevo, [{ key: 'API_KEY', public: false }])

  // Rotar una privada SIN haberla podido leer: es justo para lo que sirve.
  await vault.vars.set({ ns: 'web', key: 'API_KEY', enc: await sealed('sk-rotada') })
  assert.equal((await vault.openSecrets('web')).API_KEY, 'sk-rotada')
  assert.equal(vault.listSecrets().web.find((x) => x.key === 'API_KEY').public, false,
    'y rotarla no la vuelve visible por accidente')

  // Y también en el cajón de un aparato.
  await vault.vars.set({ pub: me, key: 'PUBLIC_URL', enc: await sealed('https://uno.example'), public: true })
  assert.equal((await fetchSecretsFrom(svcDir)).PUBLIC_URL, 'https://uno.example')

  // El valor NUNCA viaja en claro: sin sobre no hay escritura.
  await assert.rejects(vault.vars.set({ ns: 'web', key: 'API_KEY', enc: { ct: 'basura', iv: 'x', epk: 'y' } }))
})

test('el scope corta el acceso a otro namespace', async () => {
  await vault.setSecret('geo', 'DB_PASSWORD', 'nope')
  await assert.rejects(
    fetchNsWithSavedCert('geo'),
    /unauthorized: scope/
  )
})

test('un cert revocado deja de poder leer', async () => {
  const { issued } = await vault.listDevices()
  const mine = issued.find((d) => d.label === 'service:proxy')
  assert.ok(mine, 'el servicio enrolado aparece en delegations')
  await vault.revokeDevice(mine.nonce)
  await assert.rejects(fetchNsWithSavedCert('proxy'), /unauthorized: revoked/)
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
  await enrollService({
    qr: encodeInvite(qr), ns, dir: svcDir,
    onCode: ({ code }) => { vault.approveDevice(code).catch((e) => { throw e }) }
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
  await enrollService({ qr: encodeInvite(qr), ns, dir: svc, onCode: ({ code }) => { vault.approveDevice(code).catch(() => {}) } })

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
  const enc = await vault.identity.sealContent(JSON.stringify({
    items: [{ key: 'DESDE_LA_CONSOLA', value: 'valor-remoto' }]
  }))
  const r = await vault.vars.setMany({ ns, enc, by: 'test' })
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
  await enrollService({ qr: encodeInvite(qr), ns, dir: svc, onCode: ({ code }) => { vault.approveDevice(code).catch(() => {}) } })

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
  // Lo unico que persiste: su identidad, y la sal del cifrado en reposo que la protege.
  assert.deepEqual(vistos.sort(), ['atrest.salt', 'service-identity.json'],
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


test('un aparato de administracion VE el valor sin ninguna contrasena (§8.2)', async () => {
  // El motivo de todo esto: la capacidad de leer deja de ser una frase que se teclea en
  // cualquier parte y pasa a ser una llave que no sale del aparato. La boveda entrega el
  // sobre y la envoltura dirigida a ESE aparato; abrirlo es cosa suya, y ella no puede.
  const { openWrap, decryptWithCek } = await import('@dotrino/identity/content')

  // Un aparato del dueño (sin CN: no es un servicio) con su llave de cifrado.
  const par = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits'])
  const encPub = JSON.stringify(await crypto.subtle.exportKey('jwk', par.publicKey))
  const firma = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const pub = JSON.stringify(await crypto.subtle.exportKey('jwk', firma.publicKey))
  await vault.identity.admitMember({ pub, encPub, label: 'Consola', caps: ['store', 'read', 'admin'] })

  const ns = 'verlo'
  await vault.setSecret(ns, 'TOKEN', 'lo-que-quiero-ver')

  const r = await vault.vars.reveal({ ns, key: 'TOKEN', device: pub })
  assert.equal(r.pub, false, 'es privada: viene sellada, no en claro')
  assert.ok(r.wrap, 'y con la envoltura dirigida a este aparato')

  const cek = await openWrap({ wrap: r.wrap, myEncPrivateKey: par.privateKey })
  assert.equal(await decryptWithCek({ cek, envelope: r.e }), 'lo-que-quiero-ver')

  // Y a un aparato que NO esta en la lista no se le entrega ninguna envoltura.
  const ajeno = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const ajenoPub = JSON.stringify(await crypto.subtle.exportKey('jwk', ajeno.publicKey))
  await assert.rejects(() => vault.vars.reveal({ ns, key: 'TOKEN', device: ajenoPub }), /no wrapping/)
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
  const svc = await enrollService({
    qr, ns, dir, label: 'service:' + ns,
    onCode: ({ code }) => { vault.approveDevice(code).catch((e) => { throw e }) }
  })

  await vault.secrets.set(ns, 'TOKEN', 'el-secreto-del-servicio')

  const destinatarios = vault.secrets.recipientsIn(`ns:${ns}`)

  assert.ok(destinatarios.includes(svc.device.publickey), 'su servicio sí, faltaría más')
  assert.ok(destinatarios.includes('#recovery'), 'y la recuperación, que es lo que abre la frase')
  assert.equal(destinatarios.length, 2,
    'y NADIE más: ningún aparato que administre entra en un cajón que tiene dueño')
})

/**
 * LA DELEGACIÓN (§8.11): quien reparte la llave a un aparato nuevo es OTRO SERVICIO del
 * mismo cajón, no la bóveda ni quien administra.
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

test('un servicio le reparte la llave del cajón a otro que entra después', async () => {
  const ns = 'delegado'
  const { enrollService, fetchSecrets, watchSecretsChanges } = await import('../lib/src/service.js')

  const join = async (label) => {
    const { qr } = await vault.startPairing({ scope: [`vault:secrets:${ns}`], label, ttlMs: 60000 })
    const dir = tmp('svc-' + label + '-')
    const svc = await enrollService({
      qr, ns, dir, label,
      onCode: ({ code }) => { vault.approveDevice(code).catch((e) => { throw e }) }
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
    return { dir, ...await enrollService({ qr, ns, dir, label, onCode: ({ code }) => { vault.approveDevice(code).catch(() => {}) } }) }
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
