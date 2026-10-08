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

test('«me actualicé» es una noticia: dice la versión y abre la bóveda, no Pedidos', () => {
  const { avisoDe } = cargar()
  const es = avisoDe({ type: 'ring', ts: 5, why: { ev: 'updated', version: '0.147.0', from: '0.146.0' } }, 'es')
  assert.equal(es.title, 'Tu bóveda se actualizó')
  assert.equal(es.options.body, 'Ahora corre la 0.147.0.')
  assert.equal(es.options.data.url, '/vault')
  assert.equal(es.options.tag, 'dotrino-vault-updated', 'no pisa el aviso de un pedido')
  const en = avisoDe({ type: 'ring', why: { ev: 'updated', version: '0.147.0' } }, 'en')
  assert.equal(en.title, 'Your vault was updated')
  assert.equal(en.options.body, 'It now runs 0.147.0.')
  // De un APARATO: dice cuál (nombre, o su id si no tiene).
  const ag = avisoDe({ type: 'ring', why: { ev: 'updated', version: '1.2.3', product: '@dotrino/terminal-agent', label: 'portátil', deviceId: 'AB12-CD34' } }, 'es')
  assert.equal(ag.title, 'portátil se actualizó')
  assert.equal(ag.options.body, 'Ahora corre la 1.2.3.')
  assert.equal(avisoDe({ type: 'ring', why: { ev: 'updated', version: '1.2.3', product: '@dotrino/ia-agent', deviceId: 'AB12-CD34' } }, 'en').title, 'AB12-CD34 was updated')
  assert.equal(avisoDe({ type: 'ring', why: { ev: 'updated', version: '0.147.0', product: '@dotrino/vaultd' } }, 'es').title, 'Tu bóveda se actualizó')
})

test('un pedido de actualización no dice de quién en el aviso: el porqué del proxio no lo trae', () => {
  const { avisoDe } = cargar()
  assert.match(avisoDe({ type: 'ring', why: { ev: 'approval', kind: 'update', ns: 'vault', deviceId: 'AB12-CD34' } }, 'es').options.body, /^Hay una actualización esperando tu aprobación\. /)
  assert.match(avisoDe({ type: 'ring', why: { ev: 'approval', kind: 'update', ns: 'vault' } }, 'en').options.body, /^An update is waiting for your approval\. /)
})

test('«necesita permisos de administrador»: dice de quién, qué versión y que hay que instalarla a mano', () => {
  const { avisoDe } = cargar()
  const b = avisoDe({ type: 'ring', ts: 3, why: { ev: 'update-needs-root', version: '0.148.0', from: '0.147.0', product: '@dotrino/vaultd' } }, 'es')
  assert.equal(b.title, 'Tu bóveda tiene una actualización pendiente')
  assert.equal(b.options.body, 'La 0.148.0 necesita permisos de administrador: instálala a mano en esa máquina.')
  assert.equal(b.options.data.url, '/vault')
  assert.equal(b.options.tag, 'dotrino-vault-update-needs-root', 'no pisa ni un pedido ni un «se actualizó»')
  assert.equal(avisoDe({ type: 'ring', why: { ev: 'update-needs-root', version: '0.148.0' } }, 'en').title, 'Your vault has an update waiting')
  const a = avisoDe({ type: 'ring', why: { ev: 'update-needs-root', version: '1.3.0', product: '@dotrino/terminal-agent', label: 'servidor', deviceId: 'AB12-CD34' } }, 'es')
  assert.equal(a.title, 'servidor tiene una actualización pendiente')
  const e = avisoDe({ type: 'ring', why: { ev: 'update-needs-root', version: '1.3.0', product: '@dotrino/ia-agent', deviceId: 'AB12-CD34' } }, 'en')
  assert.equal(e.title, 'AB12-CD34 has an update waiting')
  assert.equal(e.options.body, '1.3.0 needs administrator rights: install it by hand on that machine.')
})
