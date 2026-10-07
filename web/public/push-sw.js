/* EL TIMBRE: despertar la bóveda —o a quien aprueba— cuando alguien pide algo.
 *
 * Este archivo se INYECTA en el service worker que genera vite-plugin-pwa
 * (`workbox.importScripts`), porque un SW generado no admite manejadores propios y
 * registrar un segundo SW le pisaría el scope al de la PWA.
 *
 * DOS TIMBRES, y el aviso dice cuál:
 *
 *   · LA BÓVEDA EN ESTA PESTAÑA (dueño, 2026-08-29): la extensión manda su petición al
 *     proxio, el destinatario no está conectado, se **encola** (hasta 24 h) y suena esto. Al
 *     pulsarlo se abre `/vault`, la bóveda se conecta y **baja la cola sola**. Ese timbre no
 *     lleva contenido: el proxio no sabe qué se pidió —va sellado—.
 *
 *   · UN PEDIDO DE APROBACIÓN, a un navegador que aprueba (dueño, 2026-09-30: «la aprobación
 *     no debe ser exclusiva del teléfono»; «es importante que se sepa el porqué»). El proxio
 *     manda en `why` qué se pide y quién —lo que ya ve del aviso de la bóveda—, y el Web Push
 *     lo trae cifrado hasta aquí. El aviso lo dice y abre `/approvals`, donde se decide con el
 *     pedido verificado contra la bóveda: esto es una pista, no la decisión.
 */
/* global self, clients */

const TEXTO = {
  es: {
    vaultTitle: 'Alguien pide algo de tu bóveda',
    vaultBody: 'Ábrela para responder. Nadie recibe nada hasta que lo hagas.',
    apvTitle: 'Tu bóveda tiene un pedido',
    apvTap: 'Toca para aprobar o denegar.',
    read: (who, ns) => `${who} pide tus claves de ${ns}`,
    write: (who, ns) => `${who} quiere guardar variables en ${ns}`,
    passwords: (who) => `${who} quiere leer una contraseña guardada`,
    update: () => 'Tu bóveda quiere actualizarse',
    incident: (who, ns) => `${who} falló la clave de la terminal de ${ns} tres veces`,
  },
  en: {
    vaultTitle: 'Something is asking your vault',
    vaultBody: 'Open it to answer. Nothing goes out until you do.',
    apvTitle: 'Your vault has a request',
    apvTap: 'Tap to approve or deny.',
    read: (who, ns) => `${who} asks for your keys of ${ns}`,
    write: (who, ns) => `${who} wants to save variables in ${ns}`,
    passwords: (who) => `${who} wants to read a saved password`,
    update: () => 'Your vault wants to update',
    incident: (who, ns) => `${who} failed the terminal code of ${ns} three times`,
  },
}

const idioma = () => (self.registration?.scope || '').includes('/en/') ? 'en' : 'es'

/**
 * El aviso que corresponde a un timbre. Pura, para poder probarla (`test/push-sw.test.mjs`).
 * @returns {{ title: string, options: object }}
 */
function avisoDe (ring, l) {
  const T = TEXTO[l] || TEXTO.es
  const why = ring && ring.why && ring.why.ev === 'approval' ? ring.why : null
  if (why) {
    const who = why.label ? `${why.label} (${why.deviceId || '?'})` : (why.deviceId || '?')
    const decir = T[why.kind] || T.read
    return {
      title: T.apvTitle,
      options: {
        body: decir(who, why.ns || '?') + ' ' + T.apvTap,
        icon: '/icon-192.png',
        badge: '/icon-192.png',
        tag: 'dotrino-vault-approval',   // uno solo: el último pedido manda
        renotify: true,
        timestamp: ring.ts || Date.now(),
        data: { url: '/approvals' },
      },
    }
  }
  return {
    title: T.vaultTitle,
    options: {
      body: T.vaultBody,
      icon: '/icon-192.png',
      badge: '/icon-192.png',
      tag: 'dotrino-vault-ring',      // uno solo: diez pedidos no son diez avisos
      renotify: true,
      timestamp: (ring && ring.ts) || Date.now(),
      data: { url: '/vault' },
    },
  }
}

self.addEventListener('push', (event) => {
  // El payload es `{ type: 'ring', ts, why? }`. Si viniera vacío o ilegible, se avisa igual:
  // que el aviso dependa de poder parsear algo sería perder el pedido por un detalle.
  let ring = null
  try { ring = event.data ? event.data.json() : null } catch (_) { /* el aviso va igual */ }
  const { title, options } = avisoDe(ring, idioma())
  event.waitUntil(self.registration.showNotification(title, options))
})

self.addEventListener('notificationclick', (event) => {
  event.notification.close()
  const destino = event.notification.data?.url || '/vault'
  event.waitUntil((async () => {
    const abiertas = await clients.matchAll({ type: 'window', includeUncontrolled: true })
    // Si ya hay una pestaña en ese sitio, se ENFOCA: abrir otra dejaría dos mostradores
    // de la misma cuenta, que es justo lo que la consola evita.
    for (const c of abiertas) {
      if (new URL(c.url).pathname.startsWith(destino)) return c.focus()
    }
    for (const c of abiertas) {
      if ('navigate' in c) { await c.navigate(destino); return c.focus() }
    }
    return clients.openWindow(destino)
  })())
})

// Para las pruebas en Node: aquí no hay `module` y no pasa nada.
if (typeof module !== 'undefined') module.exports = { avisoDe }
