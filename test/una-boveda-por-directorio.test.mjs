/**
 * CADA PROCESO, SU DIRECTORIO, Y NUNCA MEZCLADOS.
 *
 * Es la única invariante que hace falta cuando varias bóvedas viven en un mismo disco
 * (dueño, 2026-08-30). No hay datos compartidos: cada una tiene su directorio entero — su
 * identidad, sus perfiles, sus sobres — así que dos procesos nunca escriben el mismo
 * archivo. Lo que hay que impedir son los dos accidentes que rompen eso:
 *
 *   1. dos procesos sobre el MISMO directorio (`lock.js`)
 *   2. un proceso arrancando con la identidad de OTRO (`keyowner.js`)
 *
 * Y la vuelta de tuerca (dueño, 2026-08-30): el nombre de la carpeta SALE de la llave, así
 * que el segundo accidente deja de ser algo que se detecta y pasa a ser imposible de
 * escribir — dos llaves no pueden caer en la misma carpeta porque no se llaman igual. La
 * marca se queda igualmente: el nombre dice la intención, la marca comprueba el hecho (un
 * respaldo restaurado encima pone los bytes equivocados bajo el nombre correcto).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { takeLock, LOCK_FILE } from '../lib/src/lock.js'
import { assertKeyOwnsDir, keyOwnerOf, keyDirName, OWNER_FILE } from '../src/keyowner.js'
import { openProfiles } from '../src/profiles.js'
import { readJson, writeJson } from '../src/paths.js'
import { atRestFor } from '../src/atrest.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'unaboveda-'))
const rm = (d) => fs.rmSync(d, { recursive: true, force: true })

test('el primero toma el candado y el segundo se queda fuera', () => {
  const d = tmp()
  const a = takeLock(d)
  assert.throws(() => takeLock(d), (e) => e.code === 'vault-locked')
  a.release()
  takeLock(d).release()   // suelto: ahora sí
  rm(d)
})

/**
 * EL CASO QUE EL PID NO VEÍA, y por el que existe esto: el candado lo dejó otra máquina o
 * ese pid no significa nada aquí. No hay proceso local que preguntar — solo se puede
 * mirar si sigue latiendo.
 */
test('un candado de otra máquina, latiendo, NO se puede quitar', () => {
  const d = tmp()
  fs.writeFileSync(path.join(d, LOCK_FILE), JSON.stringify({ pid: 999999, host: 'otra-maquina', desde: Date.now() }))
  assert.throws(() => takeLock(d), (e) => {
    assert.equal(e.code, 'vault-locked')
    assert.match(e.message, /otra-maquina/, 'tiene que decir QUIÉN lo tiene')
    return true
  })
  rm(d)
})

test('un candado abandonado (sin latido) se recupera solo', () => {
  const d = tmp()
  const f = path.join(d, LOCK_FILE)
  fs.writeFileSync(f, JSON.stringify({ pid: 999999, host: 'la-que-se-apagó', desde: 0 }))
  const viejo = new Date(Date.now() - 120_000)
  fs.utimesSync(f, viejo, viejo)

  const l = takeLock(d)   // no debe lanzar: el dueño ya no late
  assert.equal(JSON.parse(fs.readFileSync(f, 'utf8')).pid, process.pid)
  l.release()
  rm(d)
})

test('soltar NO le quita el candado a quien me lo quitó por viejo', () => {
  const d = tmp()
  const f = path.join(d, LOCK_FILE)
  const mio = takeLock(d)
  fs.writeFileSync(f, JSON.stringify({ pid: 424242, host: 'la-otra', desde: Date.now() }))
  mio.release()
  assert.equal(JSON.parse(fs.readFileSync(f, 'utf8')).pid, 424242, 'el candado del otro sigue ahí')
  rm(d)
})

test('directorios distintos no se estorban: así se ponen varias en un disco', () => {
  const raiz = tmp()
  const a = takeLock(path.join(raiz, 'vault-a'))
  const b = takeLock(path.join(raiz, 'vault-b'))   // no debe lanzar
  a.release(); b.release()
  rm(raiz)
})

// ---------- que nadie arranque con la identidad de otro ----------

test('el directorio queda marcado con su llave, y no se le da a otra', () => {
  const d = tmp()
  assert.equal(keyOwnerOf(d), null, 'por estrenar: sin dueño')
  assertKeyOwnsDir(d, 'PUB-A')
  assert.equal(keyOwnerOf(d), 'PUB-A')

  assert.doesNotThrow(() => assertKeyOwnsDir(d, 'PUB-A'), 'la suya entra siempre')
  assert.throws(() => assertKeyOwnsDir(d, 'PUB-B'), (e) => {
    assert.equal(e.code, 'key-mismatch')
    assert.match(e.message, /Nothing was modified/)
    return true
  })
  assert.equal(keyOwnerOf(d), 'PUB-A', 'y el intento no cambió de dueño a nadie')
  rm(d)
})

test('sin llave todavía no hay nada que comparar', () => {
  const d = tmp()
  assert.doesNotThrow(() => assertKeyOwnsDir(d, null))
  assert.equal(keyOwnerOf(d), null, 'y no se marca a nadie')
  rm(d)
})

// ---------- una llave, una carpeta ----------

const nuevaPub = async () => {
  const par = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  return JSON.stringify(await crypto.subtle.exportKey('jwk', par.publicKey))
}

test('el nombre de la carpeta sale de la llave, y empieza por su huella legible', async () => {
  const pub = await nuevaPub()
  const n = await keyDirName(pub)
  assert.match(n, /^[0-9A-F]{4}-[0-9A-F]{4}-[0-9a-f]{16}$/)
  assert.equal(await keyDirName(pub), n, 'la misma llave da siempre el mismo nombre')
  assert.notEqual(await keyDirName(await nuevaPub()), n, 'otra llave, otro nombre')
})

test('dos llaves no pueden compartir carpeta: el registro las manda a la suya', async () => {
  const root = tmp()
  const p = openProfiles(root)
  const a = await p.add('A', { mintKey: nuevaPub })
  const b = await p.add('B', { mintKey: nuevaPub })

  assert.notEqual(a.id, b.id)
  assert.notEqual(p.dirOf(a.id), p.dirOf(b.id))
  // Y en el disco no queda ni rastro de la carpeta de paso.
  const hay = fs.readdirSync(path.join(root, 'p')).sort()
  assert.deepEqual(hay, [a.id, b.id].sort(), 'solo las dos carpetas, con su nombre definitivo')
  rm(root)
})

test('la MISMA llave dos veces no crea una segunda carpeta: se dice en voz alta', async () => {
  const root = tmp()
  const p = openProfiles(root)
  const pub = await nuevaPub()
  await p.add('la primera', { mintKey: async () => pub })
  await assert.rejects(() => p.add('la misma otra vez', { mintKey: async () => pub }),
    (e) => e.code === 'key-exists')
  assert.equal(fs.readdirSync(path.join(root, 'p')).length, 1, 'ni una carpeta de paso suelta')
  rm(root)
})

/**
 * LA MIGRACIÓN, que es toda la que hay: mover la data a la carpeta que le toca. Se hace
 * con la identidad cerrada, antes de abrirla.
 */
test('una carpeta vieja se muda a la carpeta de su llave, con sus datos', async () => {
  const root = tmp()
  const p = openProfiles(root)
  const pub = await nuevaPub()
  await p.add('Perfil 1', { mintKey: async () => pub })

  // Se le pone a mano el nombre viejo (el dado que se tiraba antes) y se deja su marca.
  const bueno = await keyDirName(pub)
  const viejo = 'p3f8a91c2'
  fs.renameSync(path.join(root, 'p', bueno), path.join(root, 'p', viejo))
  fs.writeFileSync(path.join(root, 'p', viejo, OWNER_FILE), JSON.stringify({ pub }))
  fs.writeFileSync(path.join(root, 'p', viejo, 'vault.json'), '{"mio":1}')
  // El registro va cifrado en reposo como todo lo demás: se toca por donde toca.
  const regFile = path.join(root, 'profiles.json')
  const reg = readJson(regFile, null, atRestFor(root))
  reg.profiles[0].id = viejo
  reg.current = viejo
  writeJson(regFile, reg, atRestFor(root))

  const p2 = openProfiles(root)                 // = reiniciar el servicio
  const ahora = await p2.ensureNamedByKey(viejo, null)

  assert.equal(ahora, bueno, 'se muda a la carpeta de su llave')
  assert.equal(fs.readFileSync(path.join(root, 'p', bueno, 'vault.json'), 'utf8'), '{"mio":1}',
    'con sus datos dentro')
  assert.ok(!fs.existsSync(path.join(root, 'p', viejo)), 'y la vieja ya no está')
  assert.equal(p2.current(), bueno, 'el registro apunta a la nueva')
  rm(root)
})

test('una carpeta que ya se llama como su llave no se toca', async () => {
  const root = tmp()
  const p = openProfiles(root)
  const pub = await nuevaPub()
  const creado = await p.add('quieto', { mintKey: async () => pub })
  assert.equal(await p.ensureNamedByKey(creado.id, null), creado.id)
  rm(root)
})

// ---------- actualizar el paquete tiene que actualizar el servicio ----------

test('sin systemd que nos levante, NO se vigila el binario', async () => {
  const { shouldWatch } = await import('../src/selfupdate.js')
  assert.equal(shouldWatch({}, '/usr/bin/dotrino-vaultd'), false, 'irse sin quien te reinicie es apagar la bóveda')
  assert.equal(shouldWatch({ INVOCATION_ID: 'x' }, '/usr/bin/node'), false, 'desde el repo o npx no es nuestro binario')
  assert.equal(shouldWatch({ INVOCATION_ID: 'x' }, '/usr/bin/dotrino-vaultd'), true)
})

test('el binario nuevo reinicia el servicio, pero solo cuando ya está quieto', async () => {
  const { watchBinary } = await import('../src/selfupdate.js')
  const d = tmp()
  const bin = path.join(d, 'dotrino-vaultd')
  fs.writeFileSync(bin, 'v1')

  let salidas = 0
  const w = watchBinary({
    log: () => {}, exit: () => { salidas++ },
    env: { INVOCATION_ID: 'x' }, execPath: bin, checkMs: 1000
  })
  assert.ok(w, 'con systemd y el binario propio, se vigila')

  const tick = () => new Promise((r) => setTimeout(r, 1200))
  await tick()
  assert.equal(salidas, 0, 'sin cambios no se va')

  // Se escribe una versión nueva: la PRIMERA pasada solo la anota (podría estar a medias).
  fs.writeFileSync(bin, 'v2-mas-largo')
  await tick()
  assert.equal(salidas, 0, 'un archivo recién visto todavía no cuenta')

  await tick()
  assert.equal(salidas, 1, 'visto quieto dos veces: ahora sí')
  w.stop(); rm(d)
})

/**
 * Actualizar renombra la carpeta y con ella el id del perfil. Quien tuviera una consola
 * abierta sigue pidiendo por el de antes, y contestarle «ese perfil no existe» es cierto
 * y no sirve para nada: lo vio el dueño con la TUI abierta durante la actualización.
 */
test('el id de antes de la mudanza sigue resolviendo', async () => {
  const root = tmp()
  const p = openProfiles(root)
  const pub = await nuevaPub()
  await p.add('Perfil 1', { mintKey: async () => pub })

  const bueno = await keyDirName(pub)
  const viejo = 'p42ab0344'
  fs.renameSync(path.join(root, 'p', bueno), path.join(root, 'p', viejo))
  fs.writeFileSync(path.join(root, 'p', viejo, OWNER_FILE), JSON.stringify({ pub }))
  const regFile = path.join(root, 'profiles.json')
  const reg = readJson(regFile, null, atRestFor(root))
  reg.profiles[0].id = viejo; reg.current = viejo
  writeJson(regFile, reg, atRestFor(root))

  const p2 = openProfiles(root)
  assert.equal(await p2.ensureNamedByKey(viejo, null), bueno)
  assert.equal(p2.resolve(viejo), bueno, 'el cliente viejo sigue acertando')
  assert.equal(p2.resolve(bueno), bueno)
  rm(root)
})

/**
 * EL NOMBRE QUE PONE LA BÓVEDA MANDA. El aparato manda el suyo al enrolarse y pisaba
 * siempre al de aquí — y como usa por defecto el apodo del PERFIL, te quedaban varios
 * dispositivos llamados igual que tú (dueño, 2026-08-31).
 *
 * Se prueba contra la MESA de verdad. Una primera versión de este test copiaba la línea
 * que decide y la comprobaba a ella: habría seguido verde con la regla invertida, que es
 * peor que no tener test.
 */
test('el nombre puesto en `pair` gana al que trae el aparato', async () => {
  const { createEnrollDesk } = await import('../lib/src/enroll.js')
  const { makeDeviceKey, signWithDevice } = await import('@dotrino/identity/capabilities')

  const master = await makeDeviceKey()
  const aparato = await makeDeviceKey()
  const vistos = []

  const desk = createEnrollDesk({
    identity: { signDelegation: async () => ({ cert: {} }) },
    iss: master.publickey,
    proxy: 'ws://x',
    send: () => {}, sendByPubkey: () => {},
    onChallenge: (c) => vistos.push(c.label)
  })

  // Dos emparejamientos: uno con nombre puesto aquí y otro sin él. En los dos el aparato
  // se presenta como «Seyacat», que es lo que hace por defecto (el apodo del perfil).
  const presentarse = async (label) => {
    const { token, qr } = await desk.startPairing({ label, ttlMs: 60000 })
    const data = {
      v: 1, token, sn: qr.sn, dpub: aparato.publickey,
      label: 'Seyacat',                       // lo que manda el aparato: el apodo del perfil
      intent: 'join', ts: Date.now(),
      commit: 'a'.repeat(64)                  // compromiso del código: aquí solo su forma
    }
    const { signature } = await signWithDevice({ privateJwk: aparato.privateJwk, data })
    await desk.handleEnroll('remitente', { data, signature })
  }

  await presentarse('teléfono de casa')
  await presentarse('')

  assert.deepEqual(vistos, ['teléfono de casa', 'Seyacat'],
    'con nombre puesto gana el tuyo; sin él, vale el que propone el aparato')
})
