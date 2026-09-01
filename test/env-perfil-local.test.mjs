/**
 * EL PERFIL LOCAL: `~/.dotrino/service/<perfil>/<ns>`.
 *
 * Antes la ruta era `<raíz>/<ns>`, y eso hacía del nombre del cajón una CLAVE GLOBAL del
 * usuario: dos bóvedas que usaran `aws` se peleaban el mismo directorio y el segundo
 * enrolamiento dejaba al primero inservible —su papel seguía existiendo en su bóveda, sin
 * identidad en disco que lo usara—. Se avisaba, pero avisar no lo arregla.
 *
 * El perfil es una ETIQUETA DE ESTA MÁQUINA: no viaja, no entra en el acta y no se compara
 * con el perfil de la bóveda. Solo separa directorios.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { serviceDir, serviceRoot, listEnrolled, isValidEnvProfile, resolveEnvProfile } from '../lib/src/env.js'

const conRaiz = (fn) => {
  const raiz = fs.mkdtempSync(path.join(os.tmpdir(), 'env-perfil-'))
  const antes = process.env.DOTRINO_ENV_HOME
  process.env.DOTRINO_ENV_HOME = raiz
  try { return fn(raiz) } finally {
    if (antes === undefined) delete process.env.DOTRINO_ENV_HOME; else process.env.DOTRINO_ENV_HOME = antes
    fs.rmSync(raiz, { recursive: true, force: true })
  }
}
const enrolar = (raiz, perfil, ns, iss) => {
  const d = perfil ? path.join(raiz, perfil, ns) : path.join(raiz, ns)
  fs.mkdirSync(d, { recursive: true })
  fs.writeFileSync(path.join(d, 'service-identity.json'), JSON.stringify({ v: 2, ns, iss, cert: { seq: 3 } }))
  return d
}

test('la ruta lleva el perfil, y sin perfil no hay ruta', () => {
  conRaiz((raiz) => {
    assert.equal(serviceDir('cepi', 'aws'), path.join(raiz, 'cepi', 'aws'))
    // Sin perfil NO se cae a un default: se para y se dice. Elegir uno por su cuenta es
    // exactamente cómo se acabaría escribiendo en el directorio de otra bóveda.
    assert.throws(() => serviceDir(null, 'aws'), /local profile/)
    assert.throws(() => serviceDir('CEPI', 'aws'), /local profile/, 'mismo alfabeto que el ns')
    assert.throws(() => serviceDir('con_guion_bajo', 'aws'), /local profile/)
  })
})

test('DOS bóvedas con un cajón que se llama IGUAL ya no se pisan', () => {
  conRaiz((raiz) => {
    const a = enrolar(raiz, 'cepi', 'aws', 'llave-de-A')
    const b = enrolar(raiz, 'trabajo', 'aws', 'llave-de-B')
    assert.notEqual(a, b, 'cada una en su sitio')
    assert.equal(JSON.parse(fs.readFileSync(path.join(a, 'service-identity.json'))).iss, 'llave-de-A')
    assert.equal(JSON.parse(fs.readFileSync(path.join(b, 'service-identity.json'))).iss, 'llave-de-B')

    const lista = listEnrolled().filter((x) => !x.legacy)
    assert.deepEqual(lista.map((x) => `${x.profile}/${x.ns}`).sort(), ['cepi/aws', 'trabajo/aws'])
  })
})

test('lo que quedó en el formato viejo se DICE, no se usa a escondidas', () => {
  conRaiz((raiz) => {
    enrolar(raiz, null, 'aws', 'llave-vieja')      // <raíz>/aws, sin perfil
    enrolar(raiz, 'cepi', 'eco', 'llave-nueva')
    const l = listEnrolled()
    const viejo = l.find((x) => x.legacy)
    assert.ok(viejo, 'se ve que está ahí')
    assert.equal(viejo.ns, 'aws')
    assert.ok(l.some((x) => x.profile === 'cepi' && x.ns === 'eco'), 'y lo nuevo sale normal')
  })
})

test('`DOTRINO_ENV_DIR` sigue mandando sobre todo (un contenedor no discute rutas)', () => {
  conRaiz(() => {
    const antes = process.env.DOTRINO_ENV_DIR
    process.env.DOTRINO_ENV_DIR = '/data/service'
    try { assert.equal(serviceDir(null, 'aws'), '/data/service', 'ni pide perfil ni valida ns') }
    finally { if (antes === undefined) delete process.env.DOTRINO_ENV_DIR; else process.env.DOTRINO_ENV_DIR = antes }
  })
})

test('el perfil se puede dar por entorno, para no repetirlo en cada comando', () => {
  const antes = process.env.DOTRINO_ENV_PROFILE
  process.env.DOTRINO_ENV_PROFILE = 'cepi'
  try {
    assert.equal(resolveEnvProfile(null), 'cepi')
    assert.equal(resolveEnvProfile('trabajo'), 'trabajo', 'la bandera gana al entorno')
  } finally { if (antes === undefined) delete process.env.DOTRINO_ENV_PROFILE; else process.env.DOTRINO_ENV_PROFILE = antes }
  assert.equal(isValidEnvProfile('aws-cepi'), true)
  assert.equal(isValidEnvProfile('Aws'), false)
})
