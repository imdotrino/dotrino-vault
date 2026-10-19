/**
 * `info` EN TODOS LOS COMANDOS (regla del dueño, 2026-09-29): el id del aparato tiene que
 * salir tal como lo enseña la bóveda (`AB12-CD34`), porque es lo que se busca en
 * `dotrino-vault members` y lo que pide `dotrino-vault caps <ID>`. `dotrino-env status`
 * enseñaba la llave en crudo (`{"key_ops":["verify"],…`) y ningún id.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { makeDeviceKey, pubkeyId } from '@dotrino/identity/capabilities'
import { deviceInfo, formatDeviceInfo, shortId } from '../lib/src/deviceInfo.js'

test('el id corto es el mismo que enseña la bóveda', async () => {
  const k = await makeDeviceKey()
  const esperado = (await pubkeyId(k.publickey)).slice(0, 8).toUpperCase()
  assert.equal(await shortId(k.publickey), esperado.slice(0, 4) + '-' + esperado.slice(4))
})

test('info de un enlace: id, bóveda, permisos y el acta del papel, y el id va primero', async () => {
  const d = await makeDeviceKey(); const v = await makeDeviceKey()
  const info = await deviceInfo({ device: d, iss: v.publickey, cert: { scope: ['vault:sign'], seq: 44 }, proxy: 'wss://x' }, { name: 'default' })
  assert.match(info.id, /^[0-9A-F]{4}-[0-9A-F]{4}$/)
  assert.equal(info.vault, await shortId(v.publickey))
  assert.equal(info.record, 44)
  const text = formatDeviceInfo(info)
  assert.ok(text.split('\n')[0].includes(info.id), 'la primera línea es el id')
  assert.match(text, /acta #44/)
  assert.ok(!text.includes('key_ops'), 'nunca la llave en crudo')
})

test('un papel del modelo viejo se dice con su fecha, que es lo que caduca', async () => {
  const d = await makeDeviceKey()
  const info = await deviceInfo({ device: d, cert: { scope: [], exp: Date.UTC(2026, 7, 9) } })
  assert.match(formatDeviceInfo(info), /modelo viejo, vence 2026-08-09/)
})

test('sin llave de aparato no se inventa un id: se para con un código', async () => {
  await assert.rejects(deviceInfo({ cert: {} }), (e) => e.code === 'not-enrolled')
})
