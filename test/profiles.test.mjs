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
import { readJson, writeJson } from '../src/paths.js'
import { atRestFor } from '../src/atrest.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'dotrino-vault-test-'))

/**
 * El registro no genera llaves: se las pide a quien llama (`mintKey`), porque el nombre de
 * la carpeta sale de la llave y acuñar una identidad no es asunto suyo. Aquí basta una
 * pública de verdad —generarla es barato— para que `keyDirName` tenga qué resumir.
 */
const llave = async () => {
  const par = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return JSON.stringify(await crypto.subtle.exportKey('jwk', par.publicKey))
}

test('migra un dir mono-perfil al primer perfil, llevándose sus datos', async () => {
  const root = tmp()
  fs.writeFileSync(path.join(root, 'identity.json'), '{"k":1}')
  fs.writeFileSync(path.join(root, 'secrets.json'), '{"s":1}')
  fs.writeFileSync(path.join(root, 'transport.json'), '{"t":1}')

  const p = openProfiles(root)
  const res = await p.migrate(llave)
  assert.equal(res.migrated, true)

  const dir = p.dirOf(res.id)
  assert.equal(fs.readFileSync(path.join(dir, 'identity.json'), 'utf8'), '{"k":1}')
  assert.equal(fs.readFileSync(path.join(dir, 'secrets.json'), 'utf8'), '{"s":1}')
  assert.ok(!fs.existsSync(path.join(root, 'identity.json')), 'la maestra ya no queda suelta en la raíz')
  // transport.json es del PROCESO (keypair del proxy-client), no del perfil: se queda.
  assert.ok(fs.existsSync(path.join(root, 'transport.json')))
  assert.equal(p.list()[0].current, true)
})

test('un dir nuevo arranca con un perfil vacío, sin migrar nada', async () => {
  const p = openProfiles(tmp())
  const res = await p.migrate(llave)
  assert.equal(res.migrated, false)
  assert.equal(p.list().length, 1)
})

test('cada perfil tiene su propio dir y el activo se elige', async () => {
  const p = openProfiles(tmp())
  await p.migrate(llave)
  const a = await p.add('Trabajo', { mintKey: llave })
  const b = await p.add('Personal', { mintKey: llave })
  assert.notEqual(p.dirOf(a.id), p.dirOf(b.id))
  assert.equal(p.list().length, 3)
  p.setCurrent(b.id)
  assert.equal(p.get(b.id).current, true)
  assert.equal(p.get(a.id).current, false)
})

test('resolve acepta id o nombre, y rechaza el ambiguo en vez de adivinar', async () => {
  const p = openProfiles(tmp())
  await p.migrate(llave)
  const a = await p.add('Trabajo', { mintKey: llave })
  assert.equal(p.resolve('Trabajo'), a.id)
  assert.equal(p.resolve('trabajo'), a.id, 'sin distinguir mayúsculas')
  assert.equal(p.resolve(a.id), a.id)
  await p.add('Trabajo', { mintKey: llave })
  assert.throws(() => p.resolve('Trabajo'), /there are 2 profiles/)
  assert.throws(() => p.resolve('nope'), /does not exist/)
})

test('sin contraseña, el perfil nunca está bloqueado', async () => {
  const p = openProfiles(tmp())
  const { id } = await p.migrate(llave)
  assert.equal(p.isProtected(id), false)
  assert.equal(p.isLocked(id), false)
})

test('la contraseña bloquea, y la correcta desbloquea', async () => {
  const p = openProfiles(tmp())
  const { id } = await p.migrate(llave)
  await p.setPassword(id, 'frase-de-prueba-larga')
  assert.equal(p.isProtected(id), true)
  assert.equal(p.isLocked(id), false, 'ponerla deja el perfil abierto en esta sesión')

  p.lock(id)
  assert.equal(p.isLocked(id), true)
  await assert.rejects(() => p.unlock(id, 'mala'), /wrong password/)
  assert.equal(p.isLocked(id), true)
  await p.unlock(id, 'frase-de-prueba-larga')
  assert.equal(p.isLocked(id), false)
})

test('el candado se relee del disco: un daemon nuevo arranca bloqueado', async () => {
  const root = tmp()
  const p = openProfiles(root)
  const { id } = await p.migrate(llave)
  await p.setPassword(id, 'frase-de-prueba-larga')

  const reopened = openProfiles(root) // = reiniciar el servicio
  assert.equal(reopened.isProtected(id), true)
  assert.equal(reopened.isLocked(id), true, 'el desbloqueo vive en memoria, no en disco')
  await reopened.unlock(id, 'frase-de-prueba-larga')
  assert.equal(reopened.isLocked(id), false)
})

test('la contraseña no se guarda: solo un verificador con sal', async () => {
  const root = tmp()
  const p = openProfiles(root)
  const { id } = await p.migrate(llave)
  await p.setPassword(id, 'frase-de-prueba-larga')
  const raw = fs.readFileSync(path.join(root, 'profiles.json'), 'utf8')
  assert.ok(!raw.includes('frase-de-prueba-larga'), 'la contraseña en claro nunca toca el disco')
  // El registro va CIFRADO en reposo, como el resto de los archivos del vault: era el
  // único que quedaba en claro, y lleva dentro el verificador del candado.
  assert.ok(!raw.includes('profiles'), 'y el registro tampoco queda legible')
  const entry = readJson(path.join(root, 'profiles.json'), null, atRestFor(root)).profiles.find((x) => x.id === id)
  // v2 = scrypt. El verificador vive en claro DENTRO del archivo, así que tiene que
  // costar lo mismo que la llave de verdad, o es el camino barato para atacarla.
  assert.equal(entry.pwd.v, 2)
  assert.ok(entry.pwd.salt && entry.pwd.verifier && !entry.pwd.iter)
})

test('con el profile locked no se puede editar ni quitar la contraseña', async () => {
  const p = openProfiles(tmp())
  const { id } = await p.migrate(llave)
  await p.add('Otro', { mintKey: llave }) // que borrar no choque antes con «no se puede borrar el único perfil»
  await p.setPassword(id, 'frase-de-prueba-larga')
  p.lock(id)
  assert.throws(() => p.rename(id, 'otro'), /profile locked/)
  assert.throws(() => p.removePassword(id), /profile locked/)
  assert.throws(() => p.remove(id), /profile locked/)
  await p.unlock(id, 'frase-de-prueba-larga')
  assert.equal(p.rename(id, 'otro').name, 'otro')
})

test('la contraseña es por perfil: bloquear uno no toca al otro', async () => {
  const p = openProfiles(tmp())
  const { id: a } = await p.migrate(llave)
  const b = await p.add('Personal', { mintKey: llave }).id
  await p.setPassword(a, 'frase-de-prueba-larga')
  p.lock(a)
  assert.equal(p.isLocked(a), true)
  assert.equal(p.isLocked(b), false)
  assert.equal(p.isProtected(b), false)
})

test('borrar un perfil elimina su dir, y el último no se puede borrar', async () => {
  const p = openProfiles(tmp())
  await p.migrate(llave)
  const b = await p.add('Personal', { mintKey: llave })
  const bdir = p.dirOf(b.id)
  fs.writeFileSync(path.join(bdir, 'identity.json'), '{}')
  p.remove(b.id)
  assert.ok(!fs.existsSync(bdir), 'se lleva la maestra del perfil')
  assert.equal(p.list().length, 1)
  assert.throws(() => p.remove(p.list()[0].id), /only profile/)
})

test('borrar el perfil activo pasa el activo a otro', async () => {
  const p = openProfiles(tmp())
  const { id: a } = await p.migrate(llave)
  const b = await p.add('Personal', { mintKey: llave })
  p.setCurrent(b.id)
  p.remove(b.id)
  assert.equal(p.current(), a)
})

test('tras 5 fallos, el freno de fuerza bruta hace esperar', async () => {
  const p = openProfiles(tmp())
  const { id } = await p.migrate(llave)
  await p.setPassword(id, 'frase-de-prueba-larga')
  p.lock(id)
  for (let i = 0; i < 5; i++) await assert.rejects(() => p.unlock(id, 'mala'), /wrong password/)
  await assert.rejects(() => p.unlock(id, 'frase-de-prueba-larga'), /too many tries/, 'ni con la buena, hasta que pase la espera')
})

test('la contraseña exige un mínimo', async () => {
  const p = openProfiles(tmp())
  const { id } = await p.migrate(llave)
  await assert.rejects(() => p.setPassword(id, '123'), /at least 12/)
  // Y cuatro dígitos tampoco, que es de donde se viene: eran 10.000 combinaciones
  // protegiendo TODO el sellado.
  await assert.rejects(() => p.setPassword(id, '1113'), { code: 'PASSWORD_TOO_SHORT' })
})

test('el freno OLVIDA los fallos viejos: un despiste de ayer no deja la bóveda cerrada hoy', async () => {
  // La regresión: la cuenta de fallos solo la borraba un acierto, así que fallar cinco
  // veces dejaba esperas exponenciales para siempre — y cada intento nuevo, incluido el
  // bueno, se rechazaba ANTES de comprobar la contraseña y alargaba la espera. En el VPS
  // del vault quedó en 10 fallos: minutos de espera por intento y la bóveda inservible
  // para su dueño.
  const root = tmp()
  const p = openProfiles(root)
  const { id } = await p.migrate(llave)
  await p.setPassword(id, 'frase-de-prueba-larga')
  p.lock(id)

  for (let i = 0; i < 5; i++) await assert.rejects(() => p.unlock(id, 'mala'), /wrong password/)
  // Con cinco fallos ya hay espera: ni la buena llega a comprobarse.
  await assert.rejects(() => p.unlock(id, 'frase-de-prueba-larga'), /too many tries/)

  // Los fallos envejecen (se retrasa el último a hace una hora, como si fuera ayer).
  const file = path.join(root, 'profiles.json')
  const reg = readJson(file, null, atRestFor(root))
  reg.profiles[0].tries.at = Date.now() - 60 * 60 * 1000
  writeJson(file, reg, atRestFor(root))

  const tomorrow = openProfiles(root)
  await tomorrow.unlock(id, 'frase-de-prueba-larga') // sin espera: se olvidaron los de ayer
  assert.equal(tomorrow.isLocked(id), false)
  assert.equal(readJson(file, null, atRestFor(root)).profiles[0].tries, undefined)
})

test('el freno SIGUE frenando una ráfaga: fallos seguidos hacen esperar', async () => {
  const p = openProfiles(tmp())
  const { id } = await p.migrate(llave)
  await p.setPassword(id, 'frase-de-prueba-larga')
  p.lock(id)
  for (let i = 0; i < 5; i++) await assert.rejects(() => p.unlock(id, 'mala'), /wrong password/)
  await assert.rejects(() => p.unlock(id, 'mala'), (e) => e.code === 'TOO_MANY_TRIES' && e.waitSec > 0)
})

test('un perfil VIEJO (verificador PBKDF2) se abre igual y asciende a scrypt', async () => {
  // Es el camino que recorre el vault de producción al actualizar: su `profiles.json`
  // trae el verificador barato, y hay que seguir abriéndolo — si no, la contraseña deja
  // de valer y con ella los secretos sellados. El ascenso ocurre al desbloquear, que es
  // el único momento en que se tiene la contraseña en la mano.
  const root = tmp()
  const p = openProfiles(root)
  const { id } = await p.migrate(llave)
  await p.setPassword(id, 'frase-de-prueba-larga')

  // Se rebaja a mano a v1, tal como lo dejó la versión anterior.
  const file = path.join(root, 'profiles.json')
  const reg = readJson(file, null, atRestFor(root))
  const salt = Buffer.from('0123456789abcdef', 'utf8').toString('base64')
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode('frase-de-prueba-larga'), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: Buffer.from(salt, 'base64'), iterations: 300000 }, km, 256)
  reg.profiles[0].pwd = { v: 1, salt, iter: 300000, verifier: Buffer.from(new Uint8Array(bits)).toString('base64') }
  writeJson(file, reg, atRestFor(root))

  const viejo = openProfiles(root)
  await viejo.unlock(id, 'frase-de-prueba-larga')
  assert.equal(viejo.isLocked(id), false, 'la contraseña de siempre sigue abriendo')

  const tras = readJson(file, null, atRestFor(root)).profiles[0]
  assert.equal(tras.pwd.v, 2, 'y queda ascendido, sin pedirle nada al dueño')
  assert.equal(tras.pwd.iter, undefined)

  // Y sigue abriendo con el verificador nuevo (y solo con la correcta).
  const otra = openProfiles(root)
  await otra.unlock(id, 'frase-de-prueba-larga')
  assert.equal(otra.isLocked(id), false)
  await assert.rejects(() => openProfiles(root).unlock(id, 'otra-cosa-cualquiera'), { code: 'WRONG_PASSWORD' })
})

// --------------------------- bloqueo automático ------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms))

test('el candado se cierra SOLO a los 5 min sin usarse', async () => {
  // La regresión que arregla: abrir la bóveda la dejaba abierta hasta que alguien la
  // cerraba a mano o reiniciaba el servicio — y el servicio de un PC no se reinicia en
  // semanas. Teclear la contraseña el lunes dejaba la consola abierta el jueves.
  const cerradas = []
  const p = openProfiles(tmp(), { autoLockMs: 60, onAutoLock: (id) => cerradas.push(id) })
  const { id } = await p.migrate(llave)
  await p.setPassword(id, 'frase-de-prueba-larga')
  await p.unlock(id, 'frase-de-prueba-larga')
  assert.equal(p.isLocked(id), false)

  await sleep(90)
  assert.equal(p.isLocked(id), true, 'vencido el plazo, vuelve a hacer falta la contraseña')
  assert.deepEqual(cerradas, [id], 'y se avisa, para poder decirlo en el log')
  assert.equal(p.get(id).until, undefined, 'ya no hay plazo que enseñar')

  // El aviso es de UNA vez: preguntar dos veces no lo repite.
  assert.equal(p.isLocked(id), true)
  assert.deepEqual(cerradas, [id])

  // Y la contraseña sigue valiendo: cerrarse solo no es olvidarla.
  await p.unlock(id, 'frase-de-prueba-larga')
  assert.equal(p.isLocked(id), false)
})

test('el plazo se cuenta desde el ÚLTIMO USO, no desde que se abrió', async () => {
  // Quien está trabajando no se puede quedar fuera a media faena: cada cosa que hace la
  // consola (`touch`) estira el plazo. Lo que un aparato pida por el proxy NO pasa por
  // ahí, y por eso no lo alarga: el candado es de la consola.
  const p = openProfiles(tmp(), { autoLockMs: 120 })
  const { id } = await p.migrate(llave)
  await p.setPassword(id, 'frase-de-prueba-larga')
  await p.unlock(id, 'frase-de-prueba-larga')

  for (let i = 0; i < 4; i++) {
    await sleep(50)
    assert.equal(p.touch(id), true, 'sigue abierta y se le estira el plazo')
  }
  assert.equal(p.isLocked(id), false, 'tras 200 ms de USO continuo con plazo de 120 ms')

  await sleep(160)
  assert.equal(p.isLocked(id), true, 'y en cuanto se para, se cierra')
  assert.equal(p.touch(id), false, 'a una cerrada no hay plazo que estirarle')
})

test('sin contraseña no hay nada que cerrar: el plazo no bloquea el perfil', async () => {
  const p = openProfiles(tmp(), { autoLockMs: 30 })
  const { id } = await p.migrate(llave)
  await p.unlock(id, '')
  await sleep(60)
  assert.equal(p.isLocked(id), false)
  assert.equal(p.get(id).until, undefined, 'y no se enseña un plazo que no existe')
})

test('la consola puede enseñar hasta cuándo sigue abierta', async () => {
  const p = openProfiles(tmp(), { autoLockMs: 5000 })
  const { id } = await p.migrate(llave)
  await p.setPassword(id, 'frase-de-prueba-larga')
  const antes = Date.now()
  await p.unlock(id, 'frase-de-prueba-larga')
  const { until } = p.get(id)
  assert.ok(until >= antes + 4000 && until <= Date.now() + 5000, `plazo raro: ${until - Date.now()} ms`)
  assert.equal(p.autoLockMs, 5000)
})

test('con autoLockMs 0 no se cierra solo (para pruebas y arranques largos)', async () => {
  const p = openProfiles(tmp(), { autoLockMs: 0 })
  const { id } = await p.migrate(llave)
  await p.setPassword(id, 'frase-de-prueba-larga')
  await p.unlock(id, 'frase-de-prueba-larga')
  await sleep(30)
  assert.equal(p.isLocked(id), false)
  assert.equal(p.get(id).until, undefined)
})

/**
 * ABIERTO TIENE QUE SIGNIFICAR ALGO.
 *
 * Antes «abierto» era solo una bandera: la llave derivada de la frase se usaba durante el
 * `unlock` y se borraba en la misma línea. Media hora después, enrolar un servicio con la
 * bóveda recién abierta fallaba con «wrong password» —envolverle la llave de su cajón
 * exige abrir la copia de recuperación— y el aparato entraba sin poder leer nada. El fallo
 * no se parecía a su causa: aparecía en el PRIMER ARRANQUE del servicio, no al enrolarlo.
 */
test('mientras está abierto se puede envolver sin volver a pedir la frase', async () => {
  const p = openProfiles(tmp())
  const { id } = await p.migrate(llave)
  await p.setPassword(id, 'frase-de-prueba-larga')

  p.lock(id)
  assert.equal(p.openKey(id), null, 'cerrado no hay llave, y por eso hay que pedir la frase')

  await p.unlock(id, 'frase-de-prueba-larga')
  const k = p.openKey(id)
  assert.ok(k instanceof Uint8Array && k.length === 32, 'abierto, la llave está a mano')
  assert.deepEqual([...k], [...await p.adminKey(id, 'frase-de-prueba-larga')], 'y es la de la frase')

  // Cerrar no es soltar la referencia: se borra el material. Lo que acota la exposición es
  // el auto-candado, así que cuando salta tiene que llevarse esto también.
  p.lock(id)
  assert.equal(p.openKey(id), null)
  assert.deepEqual([...k], new Array(32).fill(0), 'la llave se borró, no se olvidó')
})

test('el auto-candado también se lleva la llave', async () => {
  const p = openProfiles(tmp(), { autoLockMs: 30 })
  const { id } = await p.migrate(llave)
  await p.setPassword(id, 'frase-de-prueba-larga')
  await p.unlock(id, 'frase-de-prueba-larga')
  const k = p.openKey(id)
  assert.ok(k?.length === 32)

  await new Promise((r) => setTimeout(r, 60))
  assert.equal(p.isLocked(id), true, 'se cerró solo')
  assert.equal(p.openKey(id), null)
  assert.deepEqual([...k], new Array(32).fill(0))
})
