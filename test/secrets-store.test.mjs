/**
 * El store de secretos v5: dos cajones, la mezcla con el aparato encima, la visibilidad,
 * el histórico — y las dos propiedades que sostienen todo el trabajo:
 *
 *   1. **el archivo no contiene ningún valor privado en claro**, y
 *   2. **escribir no pide la frase**; lo que la pide es VER.
 *
 * Se prueba con un SELLADOR FALSO, determinista y legible. El store no hace
 * criptografía (recibe el puerto inyectado), así que aquí se comprueba la FORMA y las
 * reglas; que los sobres sean sobres de verdad lo prueba `sealer.test.mjs`.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { openSecretsStore, NeedsPassword, NeedsMigration, RECOVERY } from '../src/secretsStore.js'
import { readJson, writeJson } from '../src/paths.js'
import { atRestFor } from '../src/atrest.js'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'dotrino-secrets-'))

/** Contraseña de mentira: el sellador falso solo comprueba que sea la misma. */
const PWD = 'llave-de-prueba'
/** Con la que se cierra la copia de recuperación cuando el perfil NO tiene contraseña. */
const MAQUINA = 'llave-de-esta-maquina'

/**
 * Sellador falso: «cifrar» es envolver en un marcador reconocible. Determinista, para
 * que un test pueda afirmar exactamente qué quedó escrito. Lo importante es que respete
 * el contrato: una envoltura solo se abre con la privada que le toca, y la copia de
 * recuperación solo con la llave con la que se cerró.
 */
function fakeSealer () {
  let n = 0
  return {
    // La llave con la que se cerró va DENTRO del sobre: solo la abre esa misma. Así el
    // falso admite cualquier llave (hace falta para probar el cambio de contraseña, que
    // usa tres distintas) sin dejar de exigir que coincida.
    openMaster (blob, adminKey) {
      if (!adminKey) throw new Error('wrong password')
      if (!blob) return {}
      const [k, json] = JSON.parse(String(blob).replace(/^SEALED\(/, '').replace(/\)$/, ''))
      if (k !== String(adminKey)) throw new Error('wrong password')
      return JSON.parse(json)
    },
    sealMaster (obj, adminKey) {
      if (!adminKey) throw new Error('wrong password')
      return `SEALED(${JSON.stringify([String(adminKey), JSON.stringify(obj)])})`
    },
    // Un par de recuperación de mentira: la pública es `rec-pub-N` y su privada
    // `rec-priv-N`. Emparejan por el número, igual que uno de verdad por la curva.
    makeRecoveryPair () {
      const i = ++n
      return { pub: `rec-pub-${i}`, priv: { d: `rec-priv-${i}` } }
    },
    newKey () { return `cek-${++n}` },
    wrapForKey (cek, encPub) { return { epk: encPub, ct: `wrap(${cek})` } },
    openWrapWith (priv, wrap) {
      const esperado = String(priv?.d || priv).replace('priv', 'pub')
      if (wrap?.epk !== esperado) throw new Error('cannot open: not for this key')
      return String(wrap.ct).replace(/^wrap\(/, '').replace(/\)$/, '')
    },
    // El «cifrado» tiene que ESCONDER de verdad, aunque sea de mentira: si el falso
    // dejara el texto a la vista, los tests que afirman que el archivo no contiene
    // ningún valor privado pasarían a ser una comprobación de nada.
    encrypt (cek, value, gen = 0) { return { k: cek, gen, ct: Buffer.from(value, 'utf8').toString('base64') } },
    openValue (cek, sobre) {
      if (!cek || sobre.k !== cek) throw new Error('cannot open: wrong key')
      return Buffer.from(sobre.ct, 'base64').toString('utf8')
    },
    wrapFor (cek, members) {
      const wraps = {}; const sinLlave = []
      for (const m of members || []) {
        if (!m?.encPub) { sinLlave.push(m?.pub); continue }
        wraps[m.pub] = { epk: m.encPub, ct: `wrap(${cek})` }
      }
      return { wraps, sinLlave }
    },
    // Solo lo usa la conversión desde v4, que sí tenía copia maestra.
    cekFor (master, owner) {
      if (!master[owner]) master[owner] = `cek-${owner}-${++n}`
      return master[owner]
    },
    decrypt (master, sobre, owner) {
      const cek = master[owner]
      if (!cek || sobre.k !== cek) throw new Error('cannot open: wrong key')
      return Buffer.from(sobre.ct, 'base64').toString('utf8')
    }
  }
}

const miembros = (...pubs) => pubs.map((p) => ({ pub: p, encPub: `enc-${p}` }))
/** Una privada de miembro para el falso: `enc-A` ↔ `A`. */
const privDe = (pub) => ({ d: `enc-${pub}`.replace('enc-', 'enc-') })

const abrir = (dir, sealer, opts = {}) => openSecretsStore(dir, {
  sealer, defaultKey: () => MAQUINA, ...opts
})

/** El archivo tal cual quedó en el disco (descifrando solo el cifrado en reposo). */
const enDisco = (dir) => readJson(path.join(dir, 'secrets.json'), null, atRestFor(dir))

test('escribir NO pide la frase, y el valor no queda en claro en el disco', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })

  await s.set('proxy', 'TURN_KEY', 'secreto-de-verdad')          // sin llave ninguna
  await s.set('proxy', 'PUBLIC_URL', 'wss://proxy', true)

  const disco = enDisco(dir)
  assert.equal(disco.schemaVersion, 5)
  assert.equal(JSON.stringify(disco).includes('secreto-de-verdad'), false, 'ni rastro del valor privado')
  // NI LA PÚBLICA (dueño, 2026-09-02: «las públicas igual, codificadas en sobres; la única
  // diferencia es si se despachan o no, son políticas»). Antes se guardaba en claro y eso
  // mezclaba dos cosas distintas: a quién se le entrega sin aprobación (política) y cómo se
  // guarda (seguridad). Ahora `pub` es solo la marca de despacho.
  assert.equal(JSON.stringify(disco).includes('wss://proxy'), false, 'la pública tampoco queda en claro')
  assert.equal(disco.ns.proxy.vars.PUBLIC_URL.pub, true, 'pero sigue marcada como pública')
  assert.ok(disco.ns.proxy.vars.PUBLIC_URL.e?.ct, 'y va en sobre, como cualquier otra')
  assert.equal(disco.ns.proxy.vars.TURN_KEY.pub, false)
  assert.ok(disco.ns.proxy.vars.TURN_KEY.e.ct, 'la privada es un sobre')
  assert.equal(disco.master, undefined, 'ya NO hay copia maestra: eso era lo que pedía la frase')
  assert.ok(disco.recovery.pub, 'y sí una pública de recuperación, en claro a propósito')
})

test('la llave va a los destinatarios Y a la copia de recuperación, a nadie más', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A', 'B') })
  await s.set('proxy', 'K', 'v')

  const g = enDisco(dir).ns.proxy.keyring[0]
  assert.deepEqual(Object.keys(g.wraps).sort(), ['A', 'B', RECOVERY].sort())
})

test('UNA GENERACION POR ESCRITURA, y el llavero recoge lo que ya no abre nada', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })

  await s.set('proxy', 'K', 'uno')
  const gen1 = enDisco(dir).ns.proxy.vars.K.gen
  await s.set('proxy', 'K', 'dos')
  const disco = enDisco(dir)
  assert.equal(disco.ns.proxy.vars.K.gen, gen1 + 1, 'no se reutiliza la CEK: no se puede abrir')
  // La primera generación sigue viva porque el HISTÓRICO la referencia.
  assert.deepEqual(disco.ns.proxy.keyring.map((g) => g.gen), [gen1, gen1 + 1])
  assert.equal(disco.history.length, 1)

  // Y al borrar la variable se van las dos, con su histórico: ya no las abre nadie, y
  // dejar guardadas las versiones anteriores de algo borrado sería no haberlo borrado.
  await s.delete('proxy', 'K')
  assert.equal((enDisco(dir).ns.proxy || { keyring: [] }).keyring.length, 0)
})

test('VER un valor sí pide la frase, y con la equivocada no se abre', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await s.set('proxy', 'K', 'lo-mio')

  assert.equal(await s.reveal('ns:proxy', 'K', MAQUINA), 'lo-mio')
  await assert.rejects(() => s.reveal('ns:proxy', 'K', 'otra-cosa'), /wrong password/)
})

test('el HISTORICO guarda la version anterior, y revertir la devuelve', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })

  await s.set('proxy', 'K', 'vieja', undefined, { by: 'PCX' })
  await s.set('proxy', 'K', 'nueva', undefined, { by: 'PCX' })

  const h = s.history('ns:proxy', 'K')
  assert.equal(h.length, 1)
  assert.equal(h[0].by, 'PCX', 'quién la pisó')
  assert.equal(await s.revealHistory('ns:proxy', 'K', h[0].ts, MAQUINA), 'vieja')

  assert.equal(await s.revert('ns:proxy', 'K', h[0].ts, { adminKey: MAQUINA }), true)
  assert.equal(await s.reveal('ns:proxy', 'K', MAQUINA), 'vieja')
  assert.equal(JSON.stringify(enDisco(dir)).includes('vieja'), false, 'y sigue sin haber nada en claro')
})

test('la FIRMA del sobre dice de que acta salio; sin firmante, sale sin firma', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), {
    recipients: () => miembros('A'),
    signer: (body) => ({ seq: 7, sig: `firma(${body.owner}/${body.key}/${body.gen})` })
  })
  await s.set('proxy', 'K', 'v')
  assert.deepEqual(enDisco(dir).ns.proxy.vars.K.seal, { seq: 7, sig: 'firma(ns:proxy/K/1)' })

  const dir2 = tmp()
  const s2 = abrir(dir2, fakeSealer(), { recipients: () => miembros('A') })
  await s2.set('proxy', 'K', 'v')
  assert.equal(enDisco(dir2).ns.proxy.vars.K.seal, null, 'guardar es más importante que poder firmar')
})

test('la mezcla no cambia: el cajon del APARATO pisa al del scope', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await s.set('proxy', 'PORT', '1', true)
  await s.setDevice('A', 'PORT', '2', true)

  const b = s.bundleFor('proxy', 'A')
  // Se compara el SOBRE, no un valor: desde 2026-09-02 una pública también va sellada, así
  // que «cuál gana» se ve en cuál de los dos sobres quedó, no en un texto.
  assert.equal(b.entries.PORT.owner, 'dev:A', 'lo específico gana')
})

test('el bundle lleva SOLO las envolturas de quien pregunta', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A', 'B') })
  await s.set('proxy', 'K', 'v')

  const b = s.bundleFor('proxy', 'A')
  assert.equal(b.wraps.ns.length, 1)
  assert.equal(b.wraps.ns[0].wrap.epk, 'enc-A')
  assert.equal(JSON.stringify(b).includes('enc-B'), false, 'las llaves de sus compañeros no le hacen falta')
  assert.equal(JSON.stringify(b).includes(RECOVERY), false, 'ni la copia del dueño')
})

test('rewrap: heredar lo YA guardado sí pide la frase, y avisa de quien no tiene llave', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await s.set('proxy', 'K', 'v')

  // Entra B (con llave) y C (sin llave, todavía no la registró).
  const r = await s.rewrap('ns:proxy', [...miembros('A', 'B'), { pub: 'C' }], MAQUINA)
  assert.deepEqual(r.sinLlave, ['C'])
  assert.ok(enDisco(dir).ns.proxy.keyring[0].wraps.B, 'a B ya se le puede servir lo viejo')

  await assert.rejects(() => s.rewrap('ns:proxy', miembros('A', 'B'), 'frase-mala'), /wrong password/)
})

test('rotate: llaves nuevas, valores recifrados, y el que salio ya no abre nada', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A', 'B') })
  await s.set('proxy', 'K', 'v')
  await s.set('proxy', 'K', 'v2')          // deja una versión en el histórico
  assert.equal(s.history('ns:proxy').length, 1)

  const r = await s.rotate('ns:proxy', miembros('A'), MAQUINA)
  assert.equal(r.rotated, 1)
  const disco = enDisco(dir)
  for (const g of disco.ns.proxy.keyring) {
    assert.equal(g.wraps.B, undefined, 'B se quedó fuera de todas las generaciones')
    assert.ok(g.wraps.A && g.wraps[RECOVERY])
  }
  assert.equal(disco.history.length, 0, 'rotar es renunciar a revertir lo de antes: estaba cifrado con lo viejo')
  assert.equal(await s.reveal('ns:proxy', 'K', MAQUINA), 'v2', 'el valor sigue siendo el mismo')
})

test('unwrap: sacar a alguien del llavero NO pide la frase', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A', 'B') })
  await s.set('proxy', 'K', 'v')

  assert.equal(s.unwrap('ns:proxy', 'B'), 1)
  assert.equal(enDisco(dir).ns.proxy.keyring[0].wraps.B, undefined)
  assert.ok(enDisco(dir).ns.proxy.keyring[0].wraps.A, 'y a los demás no se les toca')
})

test('visibilidad: de publica a privada es escribir (nada); de privada a publica NO EXISTE', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await s.set('proxy', 'URL', 'wss://x', true)
  await s.set('proxy', 'K', 'v')

  assert.equal(await s.setVisibility('proxy', 'URL', false), true, 'taparla no pide nada')
  assert.equal(enDisco(dir).ns.proxy.vars.URL.pub, false)
  assert.equal(await s.reveal('ns:proxy', 'URL', MAQUINA), 'wss://x')

  // Ni con la frase correcta: destapar un secreto no es una casilla.
  await assert.rejects(() => s.setVisibility('proxy', 'K', true, MAQUINA), { code: 'PRIVATE_STAYS_PRIVATE' })
  await assert.rejects(() => s.setVisibility('proxy', 'URL', true, MAQUINA), { code: 'PRIVATE_STAYS_PRIVATE' })
  // Ni de refilon con un set --public sobre la misma clave.
  await assert.rejects(() => s.set('proxy', 'K', 'v2', true), { code: 'PRIVATE_STAYS_PRIVATE' })
  assert.equal(await s.reveal('ns:proxy', 'K', MAQUINA), 'v', 'y el valor no se toco')
  assert.equal(enDisco(dir).ns.proxy.vars.K.pub, false)
  // Un set sin decir nada conserva la visibilidad: sigue privada.
  await s.set('proxy', 'K', 'v3')
  assert.equal(enDisco(dir).ns.proxy.vars.K.pub, false)

  // El camino valido: borrarla y crearla de nuevo como publica.
  //
  // «A la vista» ya no: desde 2026-09-02 una publica va en sobre igual que una privada y la
  // marca solo dice si se despacha sin aprobacion (dueño: «la unica diferencia es si se
  // despachan o no, son politicas; dales el mismo tratamiento de seguridad»). Asi que
  // `publicOf` da NOMBRES, y para ver el valor hay que poder abrirlo, como con cualquiera.
  await s.delete('proxy', 'K')
  await s.set('proxy', 'K', 'v4', true)
  assert.deepEqual(s.publicOf('proxy'), ['K'], 'sale como publica, por su nombre')
  assert.equal(await s.reveal('ns:proxy', 'K', MAQUINA), 'v4', 'y su valor se abre, no se lee')
})

test('conversion v3 -> v5: sin frase, con respaldo, y sin cambiar ningun valor', async () => {
  const dir = tmp()
  writeJson(path.join(dir, 'secrets.json'), {
    schemaVersion: 3,
    ns: { proxy: { TURN_KEY: { v: 'secreto', pub: false }, URL: { v: 'wss://x', pub: true } } },
    dev: {}
  }, atRestFor(dir))

  const s = abrir(dir, fakeSealer())
  assert.equal(s.isLegacy(), true)
  const r = await s.migrate(() => miembros('A'))
  assert.equal(r.migrated, true)
  assert.equal(r.from, 3)

  const disco = enDisco(dir)
  assert.equal(disco.schemaVersion, 5)
  assert.equal(JSON.stringify(disco).includes('secreto'), false)
  assert.equal(await s.reveal('ns:proxy', 'TURN_KEY', MAQUINA), 'secreto')
  // LA PÚBLICA TAMBIÉN QUEDA SELLADA (dueño, 2026-09-02). Antes la conversión la dejaba en
  // claro, así que un archivo migrado conservaba valores legibles en el disco — justo lo
  // que la conversión venía a quitar. La marca sigue, porque dice a quién se le despacha.
  assert.equal(JSON.stringify(disco).includes('wss://x'), false, 'ni la pública queda en claro')
  assert.deepEqual(s.publicOf('proxy'), ['URL'], 'sigue marcada como pública')
  assert.equal(await s.reveal('ns:proxy', 'URL', MAQUINA), 'wss://x', 'y su valor no cambió')
  assert.ok(fs.existsSync(path.join(dir, 'secrets.json.v3.bak')), 'deshacer tiene que ser un mv')
})

test('conversion v4 -> v5: la frase hace falta UNA vez, y despues nunca mas', async () => {
  const dir = tmp()
  const sealer = fakeSealer()
  // Un v4 tal como lo dejaba la versión anterior: copia maestra bajo la frase.
  const master = { 'ns:proxy': 'cek-vieja' }
  writeJson(path.join(dir, 'secrets.json'), {
    schemaVersion: 4,
    ns: {
      proxy: {
        vars: { TURN_KEY: { pub: false, owner: 'ns:proxy', e: sealer.encrypt('cek-vieja', 'secreto') } },
        keyring: [{ gen: 1, createdAt: 1, wraps: { A: { epk: 'enc-A', ct: 'wrap(cek-vieja)' } } }]
      }
    },
    dev: {},
    master: sealer.sealMaster(master, PWD)
  }, atRestFor(dir))

  const s = abrir(dir, sealer, { recipients: () => miembros('A') })
  assert.equal(s.needsMigration(), true)
  await assert.rejects(() => s.set('proxy', 'OTRA', 'x'), NeedsMigration)

  await assert.rejects(() => s.migrate(() => miembros('A'), 'frase-mala'), /wrong password/)
  const r = await s.migrate(() => miembros('A'), PWD)
  assert.equal(r.from, 4)
  assert.ok(fs.existsSync(path.join(dir, 'secrets.json.v4.bak')))

  // Y a partir de aquí, escribir no pide nada.
  await s.set('proxy', 'OTRA', 'nueva')
  assert.equal(await s.reveal('ns:proxy', 'TURN_KEY', PWD), 'secreto', 'lo de antes se conserva')
  assert.equal(await s.reveal('ns:proxy', 'OTRA', PWD), 'nueva')
})

test('cambiar la contrasena: quitar y volver a poner NO pierde los secretos', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await s.set('proxy', 'K', 'v')

  // sin contraseña → con contraseña → otra → sin contraseña
  assert.equal((await s.rekeyRecovery(null, PWD)).rekeyed, true)
  assert.equal(await s.reveal('ns:proxy', 'K', PWD), 'v')
  await s.rekeyRecovery(PWD, 'otra-frase')
  assert.equal(await s.reveal('ns:proxy', 'K', 'otra-frase'), 'v')
  await s.rekeyRecovery('otra-frase', null)
  assert.equal(await s.reveal('ns:proxy', 'K', MAQUINA), 'v', 'sin frase, la llave de la máquina')
})

test('forgetDevice borra el cajon entero del aparato, y su historico', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await s.setDevice('A', 'PORT', '1')
  await s.setDevice('A', 'PORT', '2')
  assert.equal(s.history('dev:A').length, 1)

  assert.equal(s.forgetDevice('A'), 1)
  assert.deepEqual(s.listDevices(), {})
  assert.equal(s.history('dev:A').length, 0)
})

test('sin sellador: se sirve y se lista, pero no se escribe una privada', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await s.set('proxy', 'K', 'v')
  await s.set('proxy', 'URL', 'wss://x', true)

  const mudo = openSecretsStore(dir, {})            // el daemon arrancando sin nada
  assert.deepEqual(mudo.list().proxy.map((x) => x.key).sort(), ['K', 'URL'])
  // Sin sellador se listan los NOMBRES, incluidos los de las públicas — pero ningún valor:
  // desde 2026-09-02 una pública va en sobre igual que una privada.
  assert.deepEqual(mudo.publicOf('proxy'), ['URL'])
  assert.ok(mudo.bundleFor('proxy', 'A').entries.K, 'servir no necesita abrir nada')
  await assert.rejects(() => mudo.set('proxy', 'OTRA', 'x'), NeedsPassword)
})

test('batch: muchas escrituras, un guardado', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  let escrituras = 0
  const file = path.join(dir, 'secrets.json')
  const real = fs.writeFileSync
  // `writeJson` escribe en un tmp y renombra (escritura atómica): se cuenta el tmp.
  fs.writeFileSync = (...a) => { if (String(a[0]) === file + '.tmp') escrituras++; return real(...a) }
  try {
    await s.batch(async () => {
      await s.set('proxy', 'A', '1')
      await s.set('proxy', 'B', '2')
      await s.set('proxy', 'C', '3')
    })
  } finally { fs.writeFileSync = real }
  assert.equal(escrituras, 1, 'tres variables, un guardado')
})

test('las claves y los valores se siguen validando', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await assert.rejects(() => s.set('proxy', 'minusculas', 'x'), /invalid key/)
  await assert.rejects(() => s.set('proxy', 'K', ''), /non-empty/)
  await assert.rejects(() => s.set('NO VALE', 'K', 'x'), /invalid namespace/)
})

test('convertir deja UNA envoltura por cajon: un agente sin actualizar sigue abriendo', async () => {
  // Por qué importa fuera del papel: al convertir en producción, los servicios que aún no
  // se han actualizado solo saben usar UNA envoltura por cajón (la vigente). Si la
  // conversión estrenara una generación por variable, abrirían la última y fallarían con
  // el resto — o sea que convertir apagaría los servicios en vez de migrarlos.
  const dir = tmp()
  writeJson(path.join(dir, 'secrets.json'), {
    schemaVersion: 3,
    ns: { proxy: { A: { v: '1', pub: false }, B: { v: '2', pub: false }, C: { v: '3', pub: false } } },
    dev: {}
  }, atRestFor(dir))

  const s = abrir(dir, fakeSealer())
  await s.migrate(() => miembros('A'))

  const disco = enDisco(dir)
  assert.equal(disco.ns.proxy.keyring.length, 1, 'una sola generación para las tres')
  assert.deepEqual(Object.values(disco.ns.proxy.vars).map((v) => v.gen), [1, 1, 1])
  assert.equal(await s.reveal('ns:proxy', 'B', MAQUINA), '2')

  // Y lo que se escriba DESPUÉS sí estrena generación: ahí es donde hace falta el agente
  // nuevo, y por eso el orden de despliegue es agentes → daemon → conversión.
  await s.set('proxy', 'D', '4')
  assert.equal(enDisco(dir).ns.proxy.keyring.length, 2)
})

/**
 * Quien re-envuelve para un miembro nuevo es el SERVICIO (ya tiene la llave, así que no
 * gana nada). Pero un servicio no administra: por eso solo puede AÑADIR. Si pudiera
 * reemplazar, un servicio comprometido dejaría sin leer a los demás miembros del cajón
 * metiéndoles una envoltura basura — denegación de servicio disfrazada de reparto.
 */
test('una envoltura solo se AÑADE: un servicio no puede pisar la de otro', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await s.set('proxy', 'TOKEN', 'secreto')

  const gen = 1
  const wrap = { epk: '{"kty":"EC"}', iv: 'aXY=', ct: 'Y3Q=' }

  assert.equal(s.putWrap('ns:proxy', gen, 'newcomer', wrap), true, 'añadir al que no tenía, sí')
  assert.throws(() => s.putWrap('ns:proxy', gen, 'newcomer', wrap), /ya tiene envoltura/,
    'pisar la que ya está, NO')
  assert.throws(() => s.putWrap('ns:proxy', gen, 'A', wrap), /ya tiene envoltura/,
    'y menos la de otro miembro del cajón')
  assert.throws(() => s.putWrap('ns:proxy', 99, 'other', wrap), /no existe la generación/)
  assert.throws(() => s.putWrap('ns:proxy', gen, 'other', { epk: 'x' }), /mal formada/)
})

/**
 * Y lo que arregla ese añadido si alguien lo usó mal: abrir la bóveda REHACE el llavero.
 * No comprueba las envolturas —abrir una ajena es cosa de su destinatario—, las
 * restablece: quedan exactamente las que dice el acta.
 */
test('rehacer el llavero deja lo que dice el acta y nada más', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await s.set('proxy', 'TOKEN', 'secreto')
  s.putWrap('ns:proxy', 1, 'intruder', { epk: '{"kty":"EC"}', iv: 'aXY=', ct: 'Y3Q=' })
  assert.ok(s.recipientsIn('ns:proxy').includes('intruder'), 'se coló uno')

  await s.rewrap('ns:proxy', miembros('A'), null, { exact: true })
  const left = s.recipientsIn('ns:proxy')
  assert.ok(!left.includes('intruder'), 'y al rehacer, se cae')
  assert.ok(left.includes('A'), 'el miembro de verdad se queda')
  assert.ok(left.includes(RECOVERY), 'y la recuperación, que es lo que abre la frase')
})

/**
 * GUARDAR SIN VER EL VALOR (dueño, 2026-09-01).
 *
 * «La bóveda cerrada no puede ver el valor; debe confiar en la firma del admin y en el
 * contenido de esos sobres, y es la razón por la que al abrir la bóveda rehace los sobres:
 * por si alguno tiene alguna incoherencia.»
 *
 * Antes escribir hacía un rodeo: la consola sellaba el valor AL PERFIL, la bóveda lo ABRÍA
 * para sacarlo en claro y lo volvía a cerrar. Ese descifrado era el único motivo por el que
 * la llave de cifrado del perfil tenía que estar accesible con la bóveda cerrada — o sea, la
 * razón por la que una copia del disco abría todo lo dirigido al perfil.
 *
 * Que las envolturas de este test sean objetos cualesquiera NO es un atajo: es la propiedad
 * que se prueba. `putSealed` no las abre ni las mira por dentro, así que para él son opacas
 * — y por eso puede guardar con la bóveda cerrada.
 */
test('putSealed guarda el sobre sin abrirlo, y exige la envoltura de recuperación', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A', 'B') })
  const { recoveryPub, members } = await s.recipientsFor('ns:demo')
  assert.ok(recoveryPub, 'la bóveda dice a quién hay que envolver, incluida la recuperación')
  assert.deepEqual(members.map((m) => m.pub), ['A', 'B'], 'y son los que dice el acta')

  // El sobre lo fabrica QUIEN ESCRIBE. Aquí es opaco a propósito.
  const e = { iv: 'IV-DE-QUIEN-ESCRIBE', ct: 'CT-QUE-LA-BOVEDA-NO-ABRE' }
  const wraps = { [RECOVERY]: 'w-rec', A: 'w-A', B: 'w-B' }

  const r = await s.putSealed('ns:demo', 'TOKEN', { e, wraps })
  assert.equal(r.gen, 1)
  const guardado = s.bundleFor('demo').entries.TOKEN
  assert.equal(guardado.pub, false)
  assert.equal(guardado.e.ct, e.ct, 'se guardó EXACTAMENTE lo que llegó: nadie lo abrió para volver a cerrarlo')
  assert.ok(!('v' in guardado), 'y en ningún momento hubo un valor en claro')
  assert.deepEqual([...s.recipientsIn('ns:demo')].sort(), ['#recovery', 'A', 'B'])

  // SIN la de recuperación se rechaza ANTES de tocar el disco: el cajón nacería ilegible
  // para siempre y eso no lo arregla ni abrir la bóveda.
  const sinRecuperacion = { A: 'w-A', B: 'w-B' }
  await assert.rejects(
    s.putSealed('ns:demo', 'OTRA', { e, wraps: sinRecuperacion }),
    /recovery|re-wrapped/,
    'un cajón sin la envoltura de recuperación nace muerto: no se acepta')
  assert.equal('OTRA' in s.bundleFor('demo').entries, false, 'y no se escribió nada')

  fs.rmSync(dir, { recursive: true, force: true })
})

/**
 * UN VALOR QUE SE QUEDÓ SIN CIFRAR SE CIFRA AL ABRIR LA BÓVEDA.
 *
 * Hasta el 2026-09-02 una variable PÚBLICA se guardaba legible y sin sobre. Desde ese día
 * todas van selladas, y el agente rechaza el cajón entero si alguna llega sin cifrar.
 *
 * Lo que quedó roto en medio: una pública escrita antes no tiene generación ni entrada en
 * el llavero, y `rewrap` solo reenvuelve el llavero. O sea que abrir la bóveda —que es lo
 * que la consola te dice que hagas— no le creaba una envoltura nunca. Visto de verdad en
 * el cajón `aws-admin`: la consola listaba «no key yet: TEST» para cada aparato, abrir la
 * bóveda no cambiaba nada, y una variable de prueba dejaba sin leer el token de AWS que
 * estaba al lado.
 *
 * Con la bóveda abierta el valor está delante. Se cifra ahí, que es el único momento en
 * que se puede.
 */
test('rewrap sella lo que quedó en claro, y sus aparatos ya pueden leerlo', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await s.set('aws-admin', 'AWS_SECRET_ACCESS_KEY', 'el-token')

  // Una pública como las escribía la versión anterior: `v` en claro, sin `e`, sin `gen` y
  // sin nada en el llavero. Se fabrica a mano porque `set` ya no sabe escribirlas así —
  // que es justamente el motivo de que las que quedaron no se arreglen solas.
  const disco = enDisco(dir)
  disco.ns['aws-admin'].vars.TEST = { v: 'un-valor-a-la-vista', pub: true }
  writeJson(path.join(dir, 'secrets.json'), disco, atRestFor(dir))

  const s2 = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  const r = await s2.rewrap('ns:aws-admin', miembros('A'), MAQUINA, { exact: true })
  assert.equal(r.sealed, 1, 'se selló exactamente el valor que estaba en claro')

  const despues = enDisco(dir)
  const e = despues.ns['aws-admin'].vars.TEST
  assert.ok(e.e?.ct, 'TEST ya va en sobre')
  assert.equal(e.v, undefined, 'y no queda el valor suelto al lado')
  assert.equal(e.pub, true, 'sigue siendo pública: cambia cómo se guarda, no a quién se le da')
  assert.equal(JSON.stringify(despues).includes('un-valor-a-la-vista'), false, 'ni rastro en el disco')

  // Lo que motivaba todo: el aparato ya tiene con qué abrirla.
  const anillo = despues.ns['aws-admin'].keyring.find((g) => g.gen === e.gen)
  assert.ok(anillo, 'la generación nueva está en el llavero')
  assert.ok(anillo.wraps.A, 'envuelta para el miembro que dice el acta')
  assert.ok(anillo.wraps[RECOVERY], 'y para la copia de recuperación, o nacería ilegible')
})

test('lo que ya estaba sellado no se toca al reenvolver', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await s.set('proxy', 'TURN_KEY', 'secreto')
  await s.set('proxy', 'PUBLIC_URL', 'wss://proxy', true)

  const antes = enDisco(dir)
  const r = await s.rewrap('ns:proxy', miembros('A'), MAQUINA, { exact: true })
  assert.equal(r.sealed, 0, 'no había nada en claro que sellar')

  const despues = enDisco(dir)
  for (const k of ['TURN_KEY', 'PUBLIC_URL']) {
    assert.equal(despues.ns.proxy.vars[k].gen, antes.ns.proxy.vars[k].gen, `${k} conserva su generación`)
    assert.deepEqual(despues.ns.proxy.vars[k].e, antes.ns.proxy.vars[k].e, `${k} conserva su sobre`)
  }
})

/**
 * EL CAJÓN DEL PERFIL (`docs/datos-del-perfil.md`).
 *
 * Los datos de la identidad se guardan como cualquier variable —mismo sobre, mismo
 * llavero— porque son lo mismo: un valor que solo pueden leer tus aparatos. Lo que cambia
 * es que hay una TERCERA clase que no existe en las variables: lo público de verdad, en
 * claro, porque quien pregunta desde fuera no tiene ninguna llave tuya.
 */
test('el perfil se escribe con la bóveda CERRADA, como cualquier sobre', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })

  // Un dato privado es `putSealed` a secas: la bóveda no lo abre y no hace falta la frase.
  // El `ct` es opaco a propósito: el sellador falso escribe el valor DENTRO del marcador,
  // así que usar su formato aquí haría que el valor apareciera en el disco por culpa del
  // doble, no del código.
  await s.putSealed('ns:@me', 'telefono', {
    e: { iv: 'iv1', ct: 'opaco-1' },
    wraps: { A: 'W(A)', [RECOVERY]: 'W(rec)' }
  }, { by: 'AB12-CD34' })

  const disco = enDisco(dir)
  assert.ok(disco.ns['@me'].vars.telefono.e.ct, 'va en sobre')
  assert.equal(disco.ns['@me'].vars.telefono.pubv, undefined, 'y no hay ningún valor en claro al lado')

  // Y el aparato se lleva SUS envolturas, no las de otro.
  const b = s.profileBundleFor('A')
  assert.ok(b.entries.telefono, 'la entrada está')
  assert.equal(b.wraps.length, 1, 'con la envoltura de A')
  assert.equal(s.profileBundleFor('B').wraps.length, 0, 'y B no se lleva ninguna')
})

/**
 * `@me` NO ES UN NOMBRE DE CAJÓN VÁLIDO, y esa es la garantía entera: ningún servicio
 * puede llamarse así, así que nadie puede pedir el perfil por el camino de los secretos.
 * No es una comprobación que alguien pueda olvidar — es un nombre que el validador no deja
 * existir.
 */
test('nadie puede pedir el perfil por el camino de los secretos', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await assert.rejects(() => s.set('@me', 'X', 'y'), /invalid namespace/)
  assert.throws(() => s.bundleFor('@me', 'A'), /invalid namespace/)
})

test('lo público va EN CLARO y firmado: es lo que ve quien pregunta de fuera', async () => {
  const dir = tmp()
  // CON FIRMANTE: sin él no hay `seal`, que es lo correcto —una bóveda que no puede firmar
  // no finge que firmó— pero aquí lo que se prueba es justamente la firma.
  const s = abrir(dir, fakeSealer(), {
    recipients: () => miembros('A'),
    signer: async (body) => ({ seq: 1, sig: 'FIRMA(' + body.key + '#' + body.gen + ')' })
  })
  await s.profilePutPublic('nickname', 'seyacat', { by: 'AB12-CD34' })
  await s.putSealed('ns:@me', 'telefono', {
    e: { iv: 'iv1', ct: 'opaco-2' }, wraps: { A: 'W(A)', [RECOVERY]: 'W(rec)' }
  }, { by: 'AB12-CD34' })

  const pub = s.profilePublic()
  assert.equal(pub.nickname.v, 'seyacat', 'el público se lee sin ninguna llave')
  assert.ok(pub.nickname.seal, 'y va firmado, o cualquiera lo inventa en tu nombre')
  assert.equal(pub.telefono, undefined, 'lo privado NO sale por aquí')
})

/**
 * `pubv` y no `v`: un `v` suelto dentro de un paquete de VARIABLES es un error duro desde
 * el 2026-09-02 (`plaintext-var`). Aquí un valor en claro es lo correcto, así que se
 * escribe con otro nombre y aquella invariante se queda intacta.
 */
test('un dato público del perfil no rompe la regla de los valores en claro', async () => {
  const dir = tmp()
  const s = abrir(dir, fakeSealer(), { recipients: () => miembros('A') })
  await s.profilePutPublic('nickname', 'seyacat', { by: 'AB12-CD34' })
  const e = enDisco(dir).ns['@me'].vars.nickname
  assert.equal(e.v, undefined, 'no lleva `v`, que es lo que el agente rechaza')
  assert.equal(e.pubv, 'seyacat')
  assert.equal(e.cls, 'public')
})
