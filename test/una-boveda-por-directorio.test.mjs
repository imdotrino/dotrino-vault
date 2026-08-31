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
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { takeLock, LOCK_FILE } from '../lib/src/lock.js'
import { assertKeyOwnsDir, keyOwnerOf } from '../src/keyowner.js'

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
