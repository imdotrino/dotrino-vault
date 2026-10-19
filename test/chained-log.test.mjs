/**
 * LA BITÁCORA ES UNA CADENA: tocar el pasado se ve.
 *
 * Cifrarla (0.89) le dio confidencialidad y ninguna integridad — quien tuviera la llave de
 * la máquina podía reescribir una línea y nadie lo notaba. Como evidencia no valía nada, y
 * es justo lo que un auditor mira (`CUMPLIMIENTO.md` §2).
 *
 * Estos casos fijan las dos propiedades que se pidieron, y la que NO se promete.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import crypto from 'node:crypto'
import { atRestFor } from '../src/atrest.js'

const sha256 = (t) => crypto.createHash('sha256').update(t, 'utf8').digest('hex')

/** El mismo recorrido que hace `dotrino-vault activity --verify`. */
function verify (lines) {
  let prev = null; let seq = null; let checked = 0
  for (const text of lines) {
    let e; try { e = JSON.parse(text) } catch { continue }
    if (typeof e.logSeq !== 'number') continue
    if (seq !== null) {
      if (e.logSeq !== seq + 1) return { ok: false, at: e.logSeq, why: 'salto' }
      if (e.logPrev !== prev) return { ok: false, at: e.logSeq, why: 'no encadena' }
    }
    seq = e.logSeq; prev = sha256(text); checked++
  }
  return { ok: true, checked, last: seq }
}

/** Igual que `audit` en `vault.js`: los campos de la cadena, al final y con nombre propio. */
const entryOf = (n, prev, info) => JSON.stringify({ ...info, ts: 1700000000000 + n, op: 'sign', logSeq: n, logPrev: prev })

/** Escribe una cadena como la escribe el vault, y devuelve el directorio. */
function writeChain (n) {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-log-'))
  const atRest = atRestFor(dir)
  const f = path.join(dir, 'activity.log')
  let prev = null
  const plain = []
  for (let i = 1; i <= n; i++) {
    const text = entryOf(i, prev, { device: `AA00-000${i}` })
    fs.appendFileSync(f, atRest.encrypt(text) + '\n', { mode: 0o600 })
    plain.push(text)
    prev = sha256(text)
  }
  return { dir, f, atRest, plain }
}

const read = (dir, f) => {
  const atRest = atRestFor(dir)
  return fs.readFileSync(f, 'utf8').trim().split('\n').filter(Boolean).map((l) => atRest.decrypt(l))
}

test('una cadena intacta se verifica entera', () => {
  const { dir, f } = writeChain(5)
  const r = verify(read(dir, f))
  assert.equal(r.ok, true)
  assert.equal(r.checked, 5)
  assert.equal(r.last, 5)
})

test('REESCRIBIR una entrada del pasado rompe la cadena y se ve dónde', () => {
  const { dir, f, atRest, plain } = writeChain(5)
  // El atacante tiene la llave de la máquina: descifra, cambia el aparato y vuelve a cifrar.
  const manipulada = plain[2].replace('AA00-0003', 'BB11-9999')
  const lines = fs.readFileSync(f, 'utf8').trim().split('\n')
  lines[2] = atRest.encrypt(manipulada)
  fs.writeFileSync(f, lines.join('\n') + '\n')

  const r = verify(read(dir, f))
  assert.equal(r.ok, false, 'la cadena tiene que romperse')
  assert.equal(r.at, 4, 'y romperse en la SIGUIENTE, que es la que ya no encadena')
})

test('QUITAR una entrada del medio también se ve', () => {
  const { dir, f } = writeChain(5)
  const lines = fs.readFileSync(f, 'utf8').trim().split('\n')
  lines.splice(2, 1)
  fs.writeFileSync(f, lines.join('\n') + '\n')

  const r = verify(read(dir, f))
  assert.equal(r.ok, false)
  assert.equal(r.at, 4, 'el #4 viene detrás del #2: el salto salta')
})

/**
 * LO QUE NO SE PROMETE, y va escrito para que nadie lo venda de más: cortar el FINAL deja
 * un prefijo perfectamente válido. Eso no se cierra en local — pide anclar el último hash
 * fuera de la máquina (un TSA, otro aparato). Este caso existe para que la limitación esté
 * afirmada en algún sitio y no se descubra el día de una auditoría.
 */
test('cortar el FINAL no se detecta: es la limitación conocida', () => {
  const { dir, f } = writeChain(5)
  const lines = fs.readFileSync(f, 'utf8').trim().split('\n')
  fs.writeFileSync(f, lines.slice(0, 3).join('\n') + '\n')

  const r = verify(read(dir, f))
  assert.equal(r.ok, true, 'un prefijo sigue siendo una cadena válida')
  assert.equal(r.last, 3)
})

/**
 * QUIEN LLAMA NO PUEDE PISAR LA CADENA. No es una precaución teórica: `renew` ya mandaba un
 * `seq` —el del ACTA, que no tiene nada que ver con el contador de la bitácora— y con los
 * campos delante (`{ seq, prev, ...info }`) el `...info` los sobrescribía. Resultado: dos
 * entradas seguidas numeradas igual. Lo cazó el verificador contra la bitácora de
 * producción a los diez minutos de desplegarla.
 *
 * De ahí las dos decisiones que este caso fija: **nombre propio** (`logSeq`/`logPrev`, que
 * no choca con ningún campo de dominio) y **al final** (gana la cadena, pase lo que pase).
 */
test('un `info` con `seq` y `prev` NO rompe la cadena', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'vault-log-'))
  const f = path.join(dir, 'activity.log')
  const atRest = atRestFor(dir)
  let prev = null
  for (let i = 1; i <= 4; i++) {
    // Lo que manda `renew` de verdad: su propio `seq`, el del acta. Y de paso un `prev`.
    const text = entryOf(i, prev, { device: 'AA00-0001', seq: 89, prev: 'mentira' })
    fs.appendFileSync(f, atRest.encrypt(text) + '\n', { mode: 0o600 })
    prev = sha256(text)
  }
  const lines = read(dir, f)
  const r = verify(lines)
  assert.equal(r.ok, true, 'la cadena aguanta')
  assert.equal(r.last, 4)
  // Y el dato de dominio no se pierde por el camino: sigue ahí, con su nombre.
  const e = JSON.parse(lines[0])
  assert.equal(e.seq, 89, 'el `seq` del acta se conserva')
  assert.equal(e.logSeq, 1, 'y el de la bitácora es el suyo')
})
