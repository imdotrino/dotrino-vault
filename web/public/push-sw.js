/* EL TIMBRE: despertar la bóveda cuando alguien le pide algo y no está encendida.
 *
 * Este archivo se INYECTA en el service worker que genera vite-plugin-pwa
 * (`workbox.importScripts`), porque un SW generado no admite manejadores propios y
 * registrar un segundo SW le pisaría el scope al de la PWA.
 *
 * Qué pasa cuando la bóveda está cerrada (dueño, 2026-08-29): la extensión manda su
 * petición al proxio, el proxio ve que el destinatario no está conectado, la **encola**
 * (hasta 24 h) y toca este timbre. El navegador que tiene la bóveda enseña el aviso; al
 * pulsarlo se abre `/vault`, la bóveda se conecta y **se baja la cola sola** — la
 * petición que estaba esperando se atiende sin que nadie la repita.
 *
 * EL TIMBRE NO LLEVA CONTENIDO, y es a propósito: el proxio no sabe qué se pidió —va
 * sellado— y el aviso tampoco tiene por qué. Dice que alguien pide, no qué.
 */
/* global self, clients */

const TITULO = { es: 'Alguien pide algo de tu bóveda', en: 'Something is asking your vault' }
const CUERPO = {
  es: 'Ábrela para responder. Nadie recibe nada hasta que lo hagas.',
  en: 'Open it to answer. Nothing goes out until you do.',
}

const idioma = () => (self.registration?.scope || '').includes('/en/') ? 'en' : 'es'

self.addEventListener('push', (event) => {
  // El payload es `{ type: 'ring', ts }`. Si viniera vacío o ilegible, se avisa igual:
  // que el aviso dependa de poder parsear algo sería perder el pedido por un detalle.
  let ring = null
  try { ring = event.data ? event.data.json() : null } catch (_) { /* el aviso va igual */ }
  const l = idioma()
  event.waitUntil(self.registration.showNotification(TITULO[l], {
    body: CUERPO[l],
    icon: '/icon-192.png',
    badge: '/icon-192.png',
    tag: 'dotrino-vault-ring',      // uno solo: diez pedidos no son diez avisos
    renotify: true,
    timestamp: ring?.ts || Date.now(),
    data: { url: '/vault' },
  }))
})

self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  const destino = event.notification.data?.url || '/vault'
  event.waitUntil((async () => {
    const abiertas = await clients.matchAll({ type: 'window', includeUncontrolled: true })
    // Si ya hay una pestaña de la bóveda, se ENFOCA: abrir otra dejaría dos mostradores
    // de la misma cuenta, que es justo lo que la consola evita.
    for (const c of abiertas) {
      if (new URL(c.url).pathname.startsWith('/vault')) return c.focus()
    }
    for (const c of abiertas) {
      if ('navigate' in c) { await c.navigate(destino); return c.focus() }
    }
    return clients.openWindow(destino)
  })())
})
