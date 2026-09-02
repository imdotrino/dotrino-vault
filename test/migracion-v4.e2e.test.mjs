/**
 * EL CICLO DE PRODUCCIÓN COMPLETO, con vault real y proxy real:
 * un `secrets.json` v3 sirviendo en claro → el servicio estrena su llave de cifrado →
 * migración → v4 sellado, con todo el mundo leyendo igual que antes.
 *
 * Es la prueba que decide si el despliegue del VPS puede hacerse sin romper nada, así
 * que parte del estado REAL de esa máquina: un archivo v3 escrito por la versión
 * anterior. Una bóveda nueva nace ya en v4 y no pasa por este camino — por eso el
 * archivo se escribe a mano en vez de dejar que el vault lo cree.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { createRequire } from 'node:module'
import { startVault } from '../src/vault.js'
import { openSecretsStore } from '../src/secretsStore.js'
import { makeSealer } from '../src/sealer.js'
import { enrollService, fetchSecrets } from '../lib/src/service.js'
import { encodeInvite } from '../lib/src/invite.js'
import { readJson } from '../src/paths.js'
import { atRestFor } from '../src/atrest.js'

/**
 * Aprobar el emparejamiento Y conceder `unattended`.
 *
 * Desde 2026-09-01 recibir claves privadas sin aprobación es un permiso del acta y el
 * DEFECTO es pedirla: sin esto, cada servicio de este fichero se queda esperando a un
 * teléfono que aquí no existe. Es lo mismo que le pasa a un servicio de verdad al que no
 * se le concede — el permiso hay que darlo, y eso es el punto.
 */
async function aprobarYPermitir (vault, code) {
  const r = await vault.approveDevice(code)
  const sub = r?.cert?.sub
  if (!sub) return r
  const m = (await vault.identity.profileActa()).acta.members.find((x) => x.pub === sub)
  await vault.setCaps(sub, [...new Set([...(m?.caps || []), 'unattended'])])
  return r
}

const tmp = (p) => fs.mkdtempSync(path.join(os.tmpdir(), p))
const req = createRequire(import.meta.url)
process.env.NODE_ENV = 'test'
process.env.PROXY_DB_FILE = ':memory:'
process.env.PORT = '0'
const proxy = req('../../dotrino-proxy/server.js')
const url = `ws://127.0.0.1:${await proxy.start(0)}`

test('el ciclo completo: v3 en claro -> llave del agente -> migracion -> v4 sellado', async () => {
  const dir = tmp('vault-e2e-')
  const svcDir = tmp('svc-e2e-')
  const ok = (t, v) => assert.equal(!!v, true, t)

  // --- 1) EL VPS TAL COMO ESTA HOY: un secrets.json v3, escrito por la version
  // anterior, con el valor en claro. Es el caso que importa — una boveda nueva
  // nace ya en v4 y no pasa por aqui.
  const { writeJson } = await import('../src/paths.js')
  writeJson(path.join(dir, 'secrets.json'), {
    schemaVersion: 3,
    ns: { proxy: { TURN_KEY: { v: 'la-clave-de-verdad', pub: false }, PUBLIC_URL: { v: 'wss://proxy.dotrino.com', pub: true } } },
    dev: {}
  }, atRestFor(dir))
  const vault = await startVault({ dir, proxyUrl: url, log: () => {} })
  const crudo = () => JSON.stringify(readJson(path.join(dir, 'secrets.json'), null, atRestFor(dir)))
  ok('v3: arranca sin migrar (se deshace con un reinicio)', crudo().includes('la-clave-de-verdad'))

  // --- 2) El servicio se enrola: estrena llave de cifrado y lee en claro (v3).
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:proxy'], label: 'proxy1', ttlMs: 60000 })
  await enrollService({ qr: encodeInvite(qr), ns: 'proxy', dir: svcDir, onCode: ({ code }) => aprobarYPermitir(vault, code).catch(() => {}) })
  const ident = readJson(path.join(svcDir, 'service-identity.json'), null, atRestFor(svcDir))
  ok('el agente guarda su llave de cifrado (v2)', ident.v === 2 && !!ident.enc?.privateJwk)
  const m = (await vault.profileMembers()).members.find((x) => x.cn === 'proxy')
  ok('y queda en el acta como encPub', m?.canSeal === true)
  ok('lee sus variables (v3, en claro)', (await fetchSecrets({ dir: svcDir })).TURN_KEY === 'la-clave-de-verdad')

  // --- 3) LA MIGRACION. Es lo unico que exige la contrasena.
  const CLAVE = new Uint8Array(32).fill(7) // en produccion: derivada de la frase del perfil
  const store = openSecretsStore(dir, { sealer: makeSealer() })
  const miembros = (await vault.profileMembers()).members
  const r = await store.migrate((owner) => (owner.startsWith('ns:') ? miembros.filter((x) => x.cn === owner.slice(3)) : miembros), CLAVE)
  ok('migra v3 -> v4', r.migrated === true)
  ok('NADA privado queda en claro en el disco', !crudo().includes('la-clave-de-verdad'))
  // LA PUBLICA TAMPOCO (dueño, 2026-09-02): «las publicas igual, codificadas en sobres; la
  // unica diferencia es si se despachan o no». La marca dice a quien se le entrega sin
  // aprobacion, no como se guarda — asi que la conversion tambien la sella.
  ok('la publica TAMPOCO queda en claro', !crudo().includes('wss://proxy.dotrino.com'))
  ok('deja respaldo .v3.bak para deshacer', fs.existsSync(path.join(dir, 'secrets.json.v3.bak')))

  // --- 4) Con el vault ya migrado, el agente sigue leyendo — ahora abriendo sobres.
  const vault2 = await startVault({ dir, proxyUrl: url, log: () => {} })
  const leido = await fetchSecrets({ dir: svcDir })
  ok('el agente abre los sobres y lee IGUAL que antes', leido.TURN_KEY === 'la-clave-de-verdad')
  ok('y la publica tambien', leido.PUBLIC_URL === 'wss://proxy.dotrino.com')

  // --- 4b) Y SE PUEDE SEGUIR ESCRIBIENDO. Si esto fallara, migrar dejaria el vault
  // de solo lectura: es el camino que recorre `secret set` despues del despliegue.
  const tras = openSecretsStore(dir, { sealer: makeSealer() })
  await tras.set('proxy', 'NUEVA', 'puesta-despues-de-sellar', false, CLAVE)
  ok('se sigue escribiendo tras sellar', (await tras.openBundle('proxy', null, CLAVE)).NUEVA === 'puesta-despues-de-sellar')
  ok('y lo de antes sigue ahi', (await tras.openBundle('proxy', null, CLAVE)).TURN_KEY === 'la-clave-de-verdad')

  // --- 5) La propiedad de fondo: quien tenga el disco NO puede abrir sin la frase.
  // (Se prueba contra el store directo, que es lo que veria alguien con una copia:
  // el `openSecrets` del vault cae a la llave de la maquina cuando el perfil no
  // tiene contrasena, y eso esta dicho en voz alta al arrancar.)
  const conElDisco = openSecretsStore(dir, { sealer: makeSealer() })
  let cerrado = false
  try { await conElDisco.openBundle('proxy', null, new Uint8Array(32).fill(9)) } catch { cerrado = true }
  ok('con una frase EQUIVOCADA no se abre', cerrado)
  ok('con la correcta, si', (await conElDisco.openBundle('proxy', null, CLAVE)).TURN_KEY === 'la-clave-de-verdad')
  ok('rota al expulsar deja al que salio sin envoltura', (await conElDisco.rotate('ns:proxy', [], CLAVE)).gen === 2)
})


test('un aparato que llega DESPUES del sellado queda anotado, y la siguiente escritura lo salda', async () => {
  // El hueco que costo mas caro de todos, porque no hace ruido: un servicio que estrena
  // su llave de cifrado llega por el PROXIO, no por una consola, asi que no hay a quien
  // pedirle la contrasena — y sin ella la boveda no puede envolverle la llave de su
  // cajon. Antes eso se perdia en un `.catch` que solo escribia una linea de log: el
  // servicio arrancaba sin sus variables y nadie se enteraba.
  const dir = tmp('vault-tarde-')
  const svcDir = tmp('svc-tarde-')
  const CLAVE = new Uint8Array(32).fill(3)

  const vault = await startVault({ dir, proxyUrl: url, log: () => {} })
  await vault.setSecret('tarde', 'TURN_KEY', 'la-clave', false)

  // Una boveda nueva NACE en v4, asi que aqui no hay migracion: lo que se imita es
  // ponerle contrasena al perfil, que re-sella la copia maestra bajo la frase.
  assert.equal((await vault.rekeySecrets(null, CLAVE)).rekeyed, true)
  assert.deepEqual(await vault.secretDebts(), {}, 'recien sellado no se debe nada')

  // Y AHORA llega el servicio nuevo. Se le admite sin dar la contrasena, que es lo que
  // pasa cuando se aprueba desde vault.dotrino.com.
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:tarde'], label: 'tardon', ttlMs: 60000 })
  await enrollService({ qr: encodeInvite(qr), ns: 'tarde', dir: svcDir, onCode: ({ code }) => aprobarYPermitir(vault, code).catch(() => {}) })

  const debe = await vault.secretDebts()
  assert.deepEqual(Object.keys(debe), ['ns:tarde'], 'se VE (calculado, no anotado ni perdido en un log)')
  assert.equal(debe['ns:tarde'].kind, 'rewrap')
  assert.deepEqual(debe['ns:tarde'].members.map((m) => m.keys), [['TURN_KEY']], 'y dice qué variable falta')
  // Y mientras tanto NO lee: falla en voz alta en vez de arrancar con la configuracion
  // a medias, que es lo unico peor que no arrancar.
  await assert.rejects(fetchSecrets({ dir: svcDir }), /no key to open/)

  // Escribir NO lo salda, y ahora es coherente: escribir no pide la frase (§8.1) y
  // heredarle lo VIEJO obliga a abrirlo. Lo que se escriba desde ahora sí le llega.
  await vault.setSecret('tarde', 'OTRA', 'x', true)
  assert.deepEqual(Object.keys(await vault.secretDebts()), ['ns:tarde'], 'sigue debiendo lo de antes')

  // Se salda al desbloquear, que es cuando hay con qué abrir.
  await vault.settleSecretDebts(CLAVE)
  assert.deepEqual(await vault.secretDebts(), {}, 'saldado')
  assert.equal((await fetchSecrets({ dir: svcDir })).TURN_KEY, 'la-clave', 'y ya lee lo suyo')
})

test.after(() => proxy.stop?.())


test('con el perfil BLOQUEADO la boveda sirve, y aun asi no puede leer una privada', async () => {
  // Las dos mitades de la promesa, juntas, porque por separado cada una se puede
  // cumplir mal: si dejara de servir, un reinicio del PC apagaria los servicios del
  // dueño (el candado es de la CONSOLA, no de la boveda); y si pudiera leer, el
  // sellado no serviria de nada, que es justo de lo que se venia.
  const dir = tmp('vault-candado-')
  const svcDir = tmp('svc-candado-')
  const CLAVE = new Uint8Array(32).fill(11)

  let bloqueado = false
  const vault = await startVault({ dir, proxyUrl: url, log: () => {}, isLocked: () => bloqueado })
  await vault.setSecret('candado', 'TURN_KEY', 'lo-que-hay-que-proteger', false)
  const { qr } = await vault.startPairing({ scope: ['vault:secrets:candado'], label: 'svc', ttlMs: 60000 })
  await enrollService({ qr: encodeInvite(qr), ns: 'candado', dir: svcDir, onCode: ({ code }) => aprobarYPermitir(vault, code).catch(() => {}) })

  // Se le pone contraseña al perfil: la copia maestra pasa a cerrarse con la frase.
  assert.equal((await vault.rekeySecrets(null, CLAVE)).rekeyed, true)
  bloqueado = true

  // 1) SIRVE. Es lo que no se puede romper: los aparatos ya enrolados siguen leyendo.
  assert.equal((await fetchSecrets({ dir: svcDir })).TURN_KEY, 'lo-que-hay-que-proteger',
    'con el perfil bloqueado, el servicio sigue recibiendo su configuracion')

  // 2) Y NO PUEDE LEERLA ella misma sin la frase, aunque tenga el disco entero delante.
  await assert.rejects(vault.openSecrets('candado'), /password|decrypt|open/i,
    'la boveda no abre sus propias privadas sin la contraseña')
  assert.deepEqual(await vault.openSecrets('candado', null, CLAVE), { TURN_KEY: 'lo-que-hay-que-proteger' },
    'con la frase, si')
})
