/**
 * LA SUBACTA: lo decidido que todavía no selló el acta.
 *
 * Sellar es de la maestra, y con el perfil CERRADO la maestra no está. Así que una
 * renuncia no surtía NINGÚN efecto hasta que alguien iba a la máquina y tecleaba la
 * contraseña — justo el caso que la renuncia existe para cubrir: te roban el teléfono,
 * renuncias desde él, y el ladrón sigue siendo admin hasta que llegues.
 *
 * La regla dura que la hace segura sin maestra: **solo puede QUITAR, nunca dar**. De ahí
 * salen las tres propiedades que se fijan abajo.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { openSubacta, isAcceptable, OPS } from '../src/subacta.js'
import { atRestFor } from '../src/atrest.js'
import { makeRenounce } from '@dotrino/identity/acta'
import { fileURLToPath } from 'node:url'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'subacta-'))
const par = async () => {
  const k = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return {
    pub: JSON.stringify(await crypto.subtle.exportKey('jwk', k.publicKey)),
    privateJwk: await crypto.subtle.exportKey('jwk', k.privateKey)
  }
}

test('el catálogo es la regla: solo caben operaciones que QUITAN', () => {
  assert.deepEqual(OPS, ['renounce'],
    'si entra otra, tiene que quitar y venir firmada por su sujeto — y se escribe a propósito')
})

test('una renuncia bien firmada entra; una tocada no', async () => {
  const tel = await par()
  const r = await makeRenounce({ member: tel.pub, caps: ['admin'], privateJwk: tel.privateJwk })
  assert.equal(await isAcceptable(r), true)
  assert.equal(await isAcceptable({ ...r, caps: ['admin', 'sign'] }), false, 'ampliar lo que quita invalida la firma')
  assert.equal(await isAcceptable({ ...r, op: 'admit' }), false, 'una operación que DA no está en el catálogo')
  assert.equal(await isAcceptable(null), false)
})

test('nadie puede quitarle nada a otro: la firma es del sujeto', async () => {
  const tel = await par()
  const otro = await par()
  const suya = await makeRenounce({ member: otro.pub, caps: ['admin'], privateJwk: otro.privateJwk })
  // Bien firmada por `otro`, pero nombrando a `otro`: no toca al teléfono. Y una que
  // dijera `member: tel.pub` firmada por `otro` no verifica.
  const falsa = { ...suya, member: tel.pub }
  assert.equal(await isAcceptable(falsa), false,
    'si valiera, un servicio en un VPS podría dejar sin admin a tu teléfono')
})

test('sobrevive al reinicio: se guarda en disco y cifrada en reposo', async () => {
  const dir = tmp()
  const tel = await par()
  const r = await makeRenounce({ member: tel.pub, caps: ['admin'], privateJwk: tel.privateJwk })

  const s1 = openSubacta(dir, atRestFor(dir))
  assert.equal((await s1.add(r)).ok, true)
  assert.equal(s1.count, 1)

  const s2 = openSubacta(dir, atRestFor(dir))
  assert.equal(s2.count, 1, 'un reinicio no puede perder la renuncia que protege la cuenta')
  assert.equal(s2.forMember(tel.pub).length, 1)
  assert.equal(s2.forMember('otra-llave').length, 0)

  const crudo = fs.readFileSync(path.join(dir, 'subacta.json'), 'utf8')
  assert.ok(!crudo.includes('renounce'), 'va cifrada en reposo como todo lo demás')
})

test('juntar dos es unir: la misma entrada no se guarda dos veces', async () => {
  const dir = tmp()
  const tel = await par()
  const r = await makeRenounce({ member: tel.pub, caps: ['admin'], privateJwk: tel.privateJwk })
  const s = openSubacta(dir, atRestFor(dir))
  assert.equal((await s.add(r)).ok, true)
  const otra = await s.add(r)
  assert.equal(otra.ok, false)
  assert.equal(otra.reason, 'ya-estaba', 'que dos aparatos se cuenten lo mismo es lo normal, no un fallo')
  assert.equal(s.count, 1)
})

/**
 * VACIAR SOLO LO ABSORBIDO. Mientras se sella puede entrar una nueva, y tirarla sería
 * perder una renuncia sin aplicar — en el momento en que más falta hace.
 */
test('al absorber se vacía lo absorbido, no todo', async () => {
  const dir = tmp()
  const a = await par()
  const b = await par()
  const ra = await makeRenounce({ member: a.pub, caps: ['admin'], privateJwk: a.privateJwk })
  const rb = await makeRenounce({ member: b.pub, caps: ['sign'], privateJwk: b.privateJwk })
  const s = openSubacta(dir, atRestFor(dir))
  await s.add(ra)

  const enVuelo = s.drain()          // lo que se va a sellar
  await s.add(rb)                    // llega una nueva mientras tanto
  s.clear(enVuelo)

  assert.equal(s.count, 1, 'la que llegó mientras se sellaba sigue ahí')
  assert.equal(s.forMember(b.pub).length, 1)
  assert.equal(s.forMember(a.pub).length, 0)
})

/**
 * Y LO QUE ATA EL PILAR CON LA BÓVEDA: que los mostradores se lean CON la subacta en la
 * mano. Se comprueba en la fuente porque montar la bóveda entera aquí no cabe: lo que no
 * puede pasar es que alguien llame al pilar directamente y se salte la lista.
 */
test('la bóveda envuelve al acta en UN sitio, no en los diecisiete mostradores', () => {
  const src = fs.readFileSync(fileURLToPath(new URL('../src/vault.js', import.meta.url)), 'utf8')
  assert.match(src, /import \* as ActaPilar from '@dotrino\/identity\/acta'/,
    'el pilar entra con otro nombre para que `Acta` sea el envoltorio')
  for (const fn of ['memberCan', 'memberCanScope', 'memberCanReadSecrets', 'memberCanSign', 'memberScopes', 'effectiveCaps']) {
    assert.ok(new RegExp(fn + ': \\(acta, pub').test(src), `el envoltorio tiene que cubrir ${fn}`)
  }
  assert.match(src, /subacta\.forMember\(pub\)/, 'y pasar lo pendiente de ESE miembro')
})

test('el unlock absorbe, y renunciar no falla con la bóveda cerrada', () => {
  const src = fs.readFileSync(fileURLToPath(new URL('../src/vault.js', import.meta.url)), 'utf8')

  const i = src.indexOf('async takeMasterKey ()')
  assert.match(src.slice(i, i + 1200), /absorberSubacta\('unlock'\)/, 'abrir el perfil sella lo pendiente')

  const j = src.indexOf('async function handleRenounce')
  const cuerpo = src.slice(j, j + 5000)
  const guarda = cuerpo.indexOf('subacta.add(record)')
  const sella = cuerpo.indexOf('identity.absorbRenounce(record)')
  assert.ok(guarda !== -1 && guarda < sella,
    'primero se guarda (surte efecto ya) y después se intenta sellar')
  assert.match(cuerpo, /ok: true, seq, pending: seq === null/,
    'con la bóveda cerrada la respuesta sigue siendo un sí: la renuncia YA vale')
})
