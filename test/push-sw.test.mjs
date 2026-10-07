/**
 * EL AVISO DEL NAVEGADOR DICE EL PORQUÉ (dueño, 2026-09-30: «la aprobación no debe ser
 * exclusiva del teléfono»; «es importante que se sepa el porqué de la notificación»).
 * Se carga el service worker real en un contexto aislado con un `self` de mentira.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import vm from 'node:vm'

function cargar (scope = 'https://vault.dotrino.com/') {
  const ctx = { self: { registration: { scope }, addEventListener () {} }, clients: {}, module: { exports: {} }, URL }
  vm.runInNewContext(fs.readFileSync(new URL('../web/public/push-sw.js', import.meta.url), 'utf8'), ctx)
  return ctx.module.exports
}

test('un pedido de aprobación dice QUÉ se pide y QUIÉN, y abre Pedidos', () => {
  const { avisoDe } = cargar()
  const a = avisoDe({ type: 'ring', ts: 1, why: { ev: 'approval', kind: 'read', ns: 'proxy', label: 'proxy1', deviceId: '904C-1002' } }, 'es')
  assert.equal(a.title, 'Tu bóveda tiene un pedido')
  assert.match(a.options.body, /^proxy1 \(904C-1002\) pide tus claves de proxy/)
  assert.equal(a.options.data.url, '/approvals')
  const w = avisoDe({ type: 'ring', why: { ev: 'approval', kind: 'write', ns: 'miapp', deviceId: 'AB12-CD34' } }, 'es')
  assert.match(w.options.body, /^AB12-CD34 quiere guardar variables en miapp/)
  const p = avisoDe({ type: 'ring', why: { ev: 'approval', kind: 'passwords', label: 'Chrome', deviceId: 'EE00-1111' } }, 'en')
  assert.match(p.options.body, /^Chrome \(EE00-1111\) wants to read a saved password/)
  // Un INCIDENTE: quién falló la clave y en la terminal de quién. Se bloquea o se ignora.
  const i = avisoDe({ type: 'ring', why: { ev: 'approval', kind: 'incident', ns: 'CC00-2222', label: 'portátil', deviceId: 'AB12-CD34' } }, 'es')
  assert.match(i.options.body, /^portátil \(AB12-CD34\) falló la clave de la terminal de CC00-2222 tres veces/)
})

test('el timbre de la bóveda en la pestaña sigue igual (sin contenido)', () => {
  const { avisoDe } = cargar()
  const v = avisoDe({ type: 'ring', ts: 1 }, 'es')
  assert.equal(v.title, 'Alguien pide algo de tu bóveda')
  assert.equal(v.options.data.url, '/vault')
  assert.equal(avisoDe(null, 'es').options.data.url, '/vault', 'un timbre ilegible avisa igual')
})
