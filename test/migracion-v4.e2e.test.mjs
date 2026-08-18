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
  await enrollService({ qr: encodeInvite(qr), ns: 'proxy', dir: svcDir, onCode: ({ code }) => vault.approveDevice(code).catch(() => {}) })
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
  ok('la publica SI (para eso se marco)', crudo().includes('wss://proxy.dotrino.com'))
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

  await proxy.stop?.()

})
