/**
 * DE QUÉ BÓVEDA VINO: `~/.dotrino/service/<bóveda>/<ns>`.
 *
 * Antes la ruta era `<raíz>/<ns>`, y eso hacía del nombre del cajón una CLAVE GLOBAL del
 * usuario: dos bóvedas que usaran `aws` se peleaban el mismo directorio y el segundo
 * enrolamiento dejaba al primero inservible —su papel seguía existiendo en su bóveda, sin
 * identidad en disco que lo usara—. Se avisaba, pero avisar no lo arregla.
 *
 * La etiqueta es DE ESTA MÁQUINA: no viaja, no entra en el acta y no se compara con nada.
 * Solo separa directorios. Se llama `--vault` y no `--profile` porque `dotrino-vault
 * --profile` ya significa otra cosa y los dos comandos se usan seguidos.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { serviceDir, serviceRoot, listEnrolled, isValidVaultLabel, resolveVaultLabel } from '../lib/src/env.js'

const conRaiz = (fn) => {
  const raiz = fs.mkdtempSync(path.join(os.tmpdir(), 'env-perfil-'))
  const antes = process.env.DOTRINO_ENV_HOME
  process.env.DOTRINO_ENV_HOME = raiz
  try { return fn(raiz) } finally {
    if (antes === undefined) delete process.env.DOTRINO_ENV_HOME; else process.env.DOTRINO_ENV_HOME = antes
    fs.rmSync(raiz, { recursive: true, force: true })
  }
}
const enrolar = (raiz, bov, ns, iss) => {
  const d = bov ? path.join(raiz, bov, ns) : path.join(raiz, ns)
  fs.mkdirSync(d, { recursive: true })
  fs.writeFileSync(path.join(d, 'service-identity.json'), JSON.stringify({ v: 2, ns, iss, cert: { seq: 3 } }))
  return d
}

test('la ruta lleva la bóveda, y una etiqueta mal escrita no cuela', () => {
  conRaiz((raiz) => {
    assert.equal(serviceDir('cepi', 'aws'), path.join(raiz, 'cepi', 'aws'))
    // Una etiqueta MAL ESCRITA no se «arregla» buscando: se dice que no está enrolado.
    assert.throws(() => serviceDir('CEPI', 'aws'), /not enrolled/, 'mismo alfabeto que el ns')
    assert.throws(() => serviceDir('con_guion_bajo', 'aws'), /not enrolled/)
  })
})

/**
 * SIN `--vault` SE BUSCA, Y SOLO SE EXIGE SI HAY EMPATE (dueño, 2026-09-01).
 *
 * La etiqueta se hizo obligatoria para que dos bóvedas pudieran tener un cajón con el mismo
 * nombre sin pisarse — y eso lo arregla la RUTA, no la bandera. Con un solo enrolamiento de
 * ese `ns` no hay nada que desambiguar, así que pedirla era fricción sin nada a cambio.
 *
 * Con dos sí hay que elegir, y elige el dueño: se para y se dice CUÁLES son. Eso no es un
 * repliegue —no se resuelve la ambigüedad a la brava— sino lo contrario: se señala.
 */
test('sin etiqueta: si el ns está en UNA bóveda se encuentra; si está en dos, se pregunta', () => {
  conRaiz((raiz) => {
    const enrolar = (boveda, ns) => {
      fs.mkdirSync(path.join(raiz, boveda, ns), { recursive: true })
      fs.writeFileSync(path.join(raiz, boveda, ns, 'service-identity.json'), JSON.stringify({ ns }))
    }

    // Ninguno: se dice que no está enrolado y cómo enrolarlo.
    assert.throws(() => serviceDir(null, 'aws'), /not enrolled/)

    // Uno: se encuentra solo, sin `--vault`.
    enrolar('cepi', 'aws')
    assert.equal(serviceDir(null, 'aws'), path.join(raiz, 'cepi', 'aws'), 'no hay nada que elegir')

    // Otro ns en otra bóveda no estorba: se sigue resolviendo por el nombre del cajón.
    enrolar('seyacat', 'claude')
    assert.equal(serviceDir(null, 'claude'), path.join(raiz, 'seyacat', 'claude'))
    assert.equal(serviceDir(null, 'aws'), path.join(raiz, 'cepi', 'aws'))

    // Dos con el MISMO ns: se para, y el error dice cuáles son para poder elegir.
    enrolar('seyacat', 'aws')
    assert.throws(() => serviceDir(null, 'aws'), (e) => {
      assert.match(e.message, /more than one vault/)
      assert.match(e.message, /cepi/); assert.match(e.message, /seyacat/)
      assert.match(e.message, /--vault/, 'y dice cómo resolverlo')
      return true
    })
    // Y con la etiqueta puesta, cada una va a la suya.
    assert.equal(serviceDir('cepi', 'aws'), path.join(raiz, 'cepi', 'aws'))
    assert.equal(serviceDir('seyacat', 'aws'), path.join(raiz, 'seyacat', 'aws'))
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
    assert.deepEqual(lista.map((x) => `${x.vault}/${x.ns}`).sort(), ['cepi/aws', 'trabajo/aws'])
  })
})

test('lo que quedó en el formato viejo se DICE, no se usa a escondidas', () => {
  conRaiz((raiz) => {
    enrolar(raiz, null, 'aws', 'llave-vieja')      // <raíz>/aws, sin la bóveda
    enrolar(raiz, 'cepi', 'eco', 'llave-nueva')
    const l = listEnrolled()
    const viejo = l.find((x) => x.legacy)
    assert.ok(viejo, 'se ve que está ahí')
    assert.equal(viejo.ns, 'aws')
    assert.ok(l.some((x) => x.vault === 'cepi' && x.ns === 'eco'), 'y lo nuevo sale normal')
  })
})

test('`DOTRINO_ENV_DIR` sigue mandando sobre todo (un contenedor no discute rutas)', () => {
  conRaiz(() => {
    const antes = process.env.DOTRINO_ENV_DIR
    process.env.DOTRINO_ENV_DIR = '/data/service'
    try { assert.equal(serviceDir(null, 'aws'), '/data/service', 'ni pide etiqueta ni valida ns') }
    finally { if (antes === undefined) delete process.env.DOTRINO_ENV_DIR; else process.env.DOTRINO_ENV_DIR = antes }
  })
})

test('la etiqueta se puede dar por entorno, para no repetirla en cada comando', () => {
  const antes = process.env.DOTRINO_ENV_VAULT
  process.env.DOTRINO_ENV_VAULT = 'cepi'
  try {
    assert.equal(resolveVaultLabel(null), 'cepi')
    assert.equal(resolveVaultLabel('trabajo'), 'trabajo', 'la bandera gana al entorno')
  } finally { if (antes === undefined) delete process.env.DOTRINO_ENV_VAULT; else process.env.DOTRINO_ENV_VAULT = antes }
  assert.equal(isValidVaultLabel('aws-cepi'), true)
  assert.equal(isValidVaultLabel('Aws'), false)
})
