/**
 * Registro multi-perfil + candado por contraseña (verificador PBKDF2).
 * Sin red ni proxy: prueba el registro puro (`profiles.js`).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { openProfiles } from '../src/profiles.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'dotrino-vault-test-'))

test('migra un dir mono-perfil al primer perfil, llevándose sus datos', () => {
  const root = tmp()
  fs.writeFileSync(path.join(root, 'identity.json'), '{"k":1}')
  fs.writeFileSync(path.join(root, 'secrets.json'), '{"s":1}')
  fs.writeFileSync(path.join(root, 'transport.json'), '{"t":1}')

  const p = openProfiles(root)
  const res = p.migrate()
  assert.equal(res.migrated, true)

  const dir = p.dirOf(res.id)
  assert.equal(fs.readFileSync(path.join(dir, 'identity.json'), 'utf8'), '{"k":1}')
  assert.equal(fs.readFileSync(path.join(dir, 'secrets.json'), 'utf8'), '{"s":1}')
  assert.ok(!fs.existsSync(path.join(root, 'identity.json')), 'la maestra ya no queda suelta en la raíz')
  // transport.json es del PROCESO (keypair del proxy-client), no del perfil: se queda.
  assert.ok(fs.existsSync(path.join(root, 'transport.json')))
  assert.equal(p.list()[0].current, true)
})

test('un dir nuevo arranca con un perfil vacío, sin migrar nada', () => {
  const p = openProfiles(tmp())
  const res = p.migrate()
  assert.equal(res.migrated, false)
  assert.equal(p.list().length, 1)
})

test('cada perfil tiene su propio dir y el activo se elige', () => {
  const p = openProfiles(tmp())
  p.migrate()
  const a = p.add('Trabajo')
  const b = p.add('Personal')
  assert.notEqual(p.dirOf(a.id), p.dirOf(b.id))
  assert.equal(p.list().length, 3)
  p.setCurrent(b.id)
  assert.equal(p.get(b.id).current, true)
  assert.equal(p.get(a.id).current, false)
})

test('resolve acepta id o nombre, y rechaza el ambiguo en vez de adivinar', () => {
  const p = openProfiles(tmp())
  p.migrate()
  const a = p.add('Trabajo')
  assert.equal(p.resolve('Trabajo'), a.id)
  assert.equal(p.resolve('trabajo'), a.id, 'sin distinguir mayúsculas')
  assert.equal(p.resolve(a.id), a.id)
  p.add('Trabajo')
  assert.throws(() => p.resolve('Trabajo'), /hay 2 perfiles/)
  assert.throws(() => p.resolve('nope'), /no existe/)
})

test('sin contraseña, el perfil nunca está bloqueado', () => {
  const p = openProfiles(tmp())
  const { id } = p.migrate()
  assert.equal(p.isProtected(id), false)
  assert.equal(p.isLocked(id), false)
})

test('la contraseña bloquea, y la correcta desbloquea', async () => {
  const p = openProfiles(tmp())
  const { id } = p.migrate()
  await p.setPassword(id, 'secreta')
  assert.equal(p.isProtected(id), true)
  assert.equal(p.isLocked(id), false, 'ponerla deja el perfil abierto en esta sesión')

  p.lock(id)
  assert.equal(p.isLocked(id), true)
  await assert.rejects(() => p.unlock(id, 'mala'), /incorrecta/)
  assert.equal(p.isLocked(id), true)
  await p.unlock(id, 'secreta')
  assert.equal(p.isLocked(id), false)
})

test('el candado se relee del disco: un daemon nuevo arranca bloqueado', async () => {
  const root = tmp()
  const p = openProfiles(root)
  const { id } = p.migrate()
  await p.setPassword(id, 'secreta')

  const reopened = openProfiles(root) // = reiniciar el servicio
  assert.equal(reopened.isProtected(id), true)
  assert.equal(reopened.isLocked(id), true, 'el desbloqueo vive en memoria, no en disco')
  await reopened.unlock(id, 'secreta')
  assert.equal(reopened.isLocked(id), false)
})

test('la contraseña no se guarda: solo un verificador con sal', async () => {
  const root = tmp()
  const p = openProfiles(root)
  const { id } = p.migrate()
  await p.setPassword(id, 'secreta')
  const raw = fs.readFileSync(path.join(root, 'profiles.json'), 'utf8')
  assert.ok(!raw.includes('secreta'), 'la contraseña en claro nunca toca el disco')
  const entry = JSON.parse(raw).profiles.find((x) => x.id === id)
  assert.ok(entry.pwd.salt && entry.pwd.verifier && entry.pwd.iter >= 300000)
})

test('con el perfil bloqueado no se puede editar ni quitar la contraseña', async () => {
  const p = openProfiles(tmp())
  const { id } = p.migrate()
  p.add('Otro') // que borrar no choque antes con «no se puede borrar el único perfil»
  await p.setPassword(id, 'secreta')
  p.lock(id)
  assert.throws(() => p.rename(id, 'otro'), /bloqueado/)
  assert.throws(() => p.removePassword(id), /bloqueado/)
  assert.throws(() => p.remove(id), /bloqueado/)
  await p.unlock(id, 'secreta')
  assert.equal(p.rename(id, 'otro').name, 'otro')
})

test('la contraseña es por perfil: bloquear uno no toca al otro', async () => {
  const p = openProfiles(tmp())
  const { id: a } = p.migrate()
  const b = p.add('Personal').id
  await p.setPassword(a, 'secreta')
  p.lock(a)
  assert.equal(p.isLocked(a), true)
  assert.equal(p.isLocked(b), false)
  assert.equal(p.isProtected(b), false)
})

test('borrar un perfil elimina su dir, y el último no se puede borrar', () => {
  const p = openProfiles(tmp())
  p.migrate()
  const b = p.add('Personal')
  const bdir = p.dirOf(b.id)
  fs.writeFileSync(path.join(bdir, 'identity.json'), '{}')
  p.remove(b.id)
  assert.ok(!fs.existsSync(bdir), 'se lleva la maestra del perfil')
  assert.equal(p.list().length, 1)
  assert.throws(() => p.remove(p.list()[0].id), /único perfil/)
})

test('borrar el perfil activo pasa el activo a otro', () => {
  const p = openProfiles(tmp())
  const { id: a } = p.migrate()
  const b = p.add('Personal')
  p.setCurrent(b.id)
  p.remove(b.id)
  assert.equal(p.current(), a)
})

test('tras 5 fallos, el freno de fuerza bruta hace esperar', async () => {
  const p = openProfiles(tmp())
  const { id } = p.migrate()
  await p.setPassword(id, 'secreta')
  p.lock(id)
  for (let i = 0; i < 5; i++) await assert.rejects(() => p.unlock(id, 'mala'), /incorrecta/)
  await assert.rejects(() => p.unlock(id, 'secreta'), /demasiados intentos/, 'ni con la buena, hasta que pase la espera')
})

test('la contraseña exige un mínimo', async () => {
  const p = openProfiles(tmp())
  const { id } = p.migrate()
  await assert.rejects(() => p.setPassword(id, '123'), /al menos 4/)
})
