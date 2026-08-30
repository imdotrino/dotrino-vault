/**
 * UN REGISTRO POR ESCRITOR (`lib/src/oplog.js`).
 *
 * Lo que hay que probar no es que escriba: es que DOS bóvedas escribiendo el mismo dato
 * acaben viendo lo mismo, y que lo que no debería contar no cuente.
 *
 *   1. dos escritores concurrentes NO se pisan (es el fallo que esto viene a cerrar)
 *   2. los dos calculan EL MISMO orden, sin hablar entre ellos y sin relojes
 *   3. la cadena de cada escritor detecta que le quitaron o le cambiaron una entrada
 *   4. quien el acta no reconoce se descarta — y se cuenta, no se ignora en silencio
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { openOpLog, writerFile } from '../lib/src/oplog.js'
import { makeDeviceKey, signWithDevice, verifyDeviceSig } from '@dotrino/identity/capabilities'

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'oplog-'))
const rm = (d) => fs.rmSync(d, { recursive: true, force: true })

/** Un escritor con su llave de verdad: firmar y verificar es la mitad del contrato. */
async function escritor (dir) {
  const k = await makeDeviceKey()
  return {
    pub: k.publickey,
    log: openOpLog(dir, {
      writer: k.publickey,
      sign: async (body) => (await signWithDevice({ privateJwk: k.privateJwk, data: body })).signature,
      verify: verifyDeviceSig
    })
  }
}

test('dos escritores a la vez NO se pisan: cada uno escribe en SU archivo', async () => {
  const d = tmp()
  const A = await escritor(d)
  const B = await escritor(d)

  // A la vez, sin coordinarse. Esto es exactamente lo que hoy se pierde.
  await Promise.all([
    A.log.append({ op: 'set', k: 'tema', v: 'oscuro' }, { lamport: 1 }),
    B.log.append({ op: 'set', k: 'idioma', v: 'es' }, { lamport: 1 })
  ])

  const r = await A.log.replay()
  assert.equal(r.escritores, 2, 'un archivo por escritor')
  assert.equal(r.ops.length, 2, 'las DOS operaciones sobreviven: ninguna pisó a la otra')
  assert.deepEqual(r.ops.map((e) => e.op.k).sort(), ['idioma', 'tema'])
  rm(d)
})

test('los dos calculan EL MISMO orden, sin hablarse', async () => {
  const d = tmp()
  const A = await escritor(d)
  const B = await escritor(d)

  await A.log.append({ op: 'a1' }, { lamport: 1 })
  await B.log.append({ op: 'b1' }, { lamport: 1 })   // mismo lamport: empate a propósito
  // B ha visto lo de A, así que lo suyo va DESPUÉS: eso es la causalidad del reloj.
  const visto = (await B.log.replay()).lamport
  await B.log.append({ op: 'b2' }, { lamport: visto + 1 })

  const desdeA = (await A.log.replay()).ops.map((e) => e.op.op)
  const desdeB = (await B.log.replay()).ops.map((e) => e.op.op)
  assert.deepEqual(desdeA, desdeB, 'el orden no puede depender de quién lo lea')
  assert.equal(desdeA[desdeA.length - 1], 'b2', 'lo que se escribió sabiendo el resto va al final')
  rm(d)
})

test('el orden NO depende de la hora: un reloj atrasado no reescribe nada', async () => {
  const d = tmp()
  const A = await escritor(d)
  const B = await escritor(d)
  await A.log.append({ op: 'primero' }, { lamport: 1 })
  await B.log.append({ op: 'segundo' }, { lamport: 2 })

  // B miente con su `ts` poniéndolo muy atrás. Si el orden fuera por hora, se colaría
  // delante; como va por Lamport, no cambia nada.
  const f = path.join(d, 'log', writerFile(B.pub))
  const linea = JSON.parse(fs.readFileSync(f, 'utf8').trim())
  linea.ts = 0
  fs.writeFileSync(f, JSON.stringify(linea) + '\n')

  const r = await A.log.replay()
  // La firma ya no cuadra (se tocó el cuerpo), así que además se descarta: mentir en el
  // `ts` no es gratis ni aunque el orden lo ignorara.
  assert.equal(r.ops.filter((e) => e.op.op === 'segundo').length, 0)
  assert.equal(r.descartadas, 1, 'y se CUENTA: una entrada descartada no se ignora en silencio')
  rm(d)
})

test('la cadena detecta que le quitaron una entrada del medio', async () => {
  const d = tmp()
  const A = await escritor(d)
  await A.log.append({ op: 'uno' }, { lamport: 1 })
  await A.log.append({ op: 'dos' }, { lamport: 2 })
  await A.log.append({ op: 'tres' }, { lamport: 3 })
  assert.equal((await A.log.replay()).ops.length, 3)

  // Fuera la del medio. Cada entrada apunta al hash de la anterior, así que la tercera
  // deja de encadenar y se cae — con ella y no antes: lo que había hasta el corte sí vale.
  const f = path.join(d, 'log', writerFile(A.pub))
  const lineas = fs.readFileSync(f, 'utf8').trim().split('\n')
  fs.writeFileSync(f, [lineas[0], lineas[2]].join('\n') + '\n')

  const r = await A.log.replay()
  assert.deepEqual(r.ops.map((e) => e.op.op), ['uno'], 'se conserva lo anterior al corte, no más')
  assert.equal(r.descartadas, 1)
  rm(d)
})

test('quien el acta no reconoce se descarta, y se cuenta', async () => {
  const d = tmp()
  const A = await escritor(d)
  const intruso = await escritor(d)
  await A.log.append({ op: 'mio' }, { lamport: 1 })
  await intruso.log.append({ op: 'ajeno' }, { lamport: 1 })

  // `puedeEscribir` sale del acta: este módulo no inventa autoridad, la hereda.
  const r = await A.log.replay({ puedeEscribir: (pub) => pub === A.pub })
  assert.deepEqual(r.ops.map((e) => e.op.op), ['mio'])
  assert.equal(r.descartadas, 1)

  // Y sin el filtro entra: la diferencia la hace el acta, no el disco.
  assert.equal((await A.log.replay()).ops.length, 2)
  rm(d)
})

test('cifrado en reposo POR LÍNEA: se sigue pudiendo añadir', async () => {
  const { atRestFor } = await import('../src/atrest.js')
  const d = tmp()
  const k = await makeDeviceKey()
  const log = openOpLog(d, {
    writer: k.publickey,
    sign: async (body) => (await signWithDevice({ privateJwk: k.privateJwk, data: body })).signature,
    verify: verifyDeviceSig,
    atRest: atRestFor(d)
  })
  await log.append({ op: 'set', k: 'nota', v: 'SECRETO' }, { lamport: 1 })
  await log.append({ op: 'set', k: 'otra', v: 'TAMBIEN' }, { lamport: 2 })

  const crudo = fs.readFileSync(path.join(d, 'log', writerFile(k.publickey)), 'utf8')
  assert.ok(!crudo.includes('SECRETO'), 'el contenido no puede verse en el disco')
  assert.ok(!crudo.includes('TAMBIEN'))
  assert.equal(crudo.trim().split('\n').length, 2, 'dos líneas: añadir sigue funcionando')
  assert.equal((await log.replay()).ops.length, 2)
  rm(d)
})

/**
 * LA PROYECCIÓN, que es lo que convierte esto en un reemplazo del JSON mutable: dos
 * bóvedas escriben lo suyo, y las dos acaban viendo EXACTAMENTE el mismo estado.
 */
test('dos bóvedas, un estado: la vista sale igual en las dos', async () => {
  const { project } = await import('../lib/src/oplog.js')
  const d = tmp()
  const A = await escritor(d)
  const B = await escritor(d)

  await A.log.append({ op: 'set', k: 'tema', v: 'oscuro' }, { lamport: 1 })
  await B.log.append({ op: 'set', k: 'idioma', v: 'es' }, { lamport: 1 })
  // B ve lo de A y cambia algo que A también tocó: gana el último del orden común.
  const visto = (await B.log.replay()).lamport
  await B.log.append({ op: 'set', k: 'tema', v: 'claro' }, { lamport: visto + 1 })

  const vistaA = project((await A.log.replay()).ops)
  const vistaB = project((await B.log.replay()).ops)
  assert.deepEqual(vistaA, vistaB, 'la vista no puede depender de quién la calcule')
  assert.deepEqual(vistaA, { tema: 'claro', idioma: 'es' })

  // Y borrar es una operación más, no un hueco en un archivo.
  await A.log.append({ op: 'del', k: 'idioma' }, { lamport: (await A.log.replay()).lamport + 1 })
  assert.deepEqual(project((await B.log.replay()).ops), { tema: 'claro' })
  rm(d)
})
