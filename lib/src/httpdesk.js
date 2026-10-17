/**
 * httpdesk.js — HABLARLE A UNA BÓVEDA QUE SOLO ATIENDE PETICIONES.
 *
 * Una bóveda en una función (AWS Lambda) no puede quedarse conectada al proxio: solo existe
 * mientras dura una petición. Así que se le habla por HTTP: un POST lleva el mensaje y la
 * respuesta trae lo que la bóveda contestó. Prueba de concepto, ver `lambda/README.md`.
 *
 * Es EL MISMO PROTOCOLO que el mostrador local (`./localdesk.js`) y que el proxio: lo que
 * viaja es `{type, data, signature, cert}` y la bóveda lo comprueba igual, contra el
 * certificado y contra el acta. **Alcanzar la URL no autoriza nada.**
 *
 * Se hace pasar por un cliente del proxio, igual que el mostrador local, para que quien lo
 * use no tenga que saber por dónde va.
 *
 * Lo que NO hace, dicho: una respuesta que la bóveda mande DESPUÉS (el resultado de una
 * aprobación, un aviso de cambio) no llega, porque no hay conexión que la traiga. Solo
 * vale para lo que se contesta en el acto.
 */

/** La URL del mostrador, si quien despliega la puso. Sin ella, este camino no existe. */
export const httpDeskUrl = (env = process.env) => env.DOTRINO_VAULT_URL || null

/**
 * Devuelve algo con la forma de un cliente del proxio. Un fallo de red o un estado HTTP
 * que no sea 200 llega como un `vault.error` con su `code`: quien llama no debe confundir
 * «no contesta» con «no hay nada».
 *
 * @param {{ url: string, timeoutMs?: number }} opts
 */
export function connectHttp ({ url, timeoutMs = 30000 }) {
  if (!url) throw Object.assign(new Error('connectHttp: url is required'), { code: 'no-desk-url' })
  const oyentes = new Set()
  const emitir = (p) => { for (const fn of oyentes) { try { fn('desk', p) } catch (_) {} } }

  const enviar = (obj) => {
    // Se manda sin esperar, como `send` del proxio: la respuesta llega por `on('message')`.
    // Un fallo se convierte en un `vault.error`, que es lo que quien escucha ya sabe leer;
    // callarlo dejaría al que pidió esperando hasta su timeout sin saber por qué.
    ;(async () => {
      const ctl = new AbortController()
      const t = setTimeout(() => ctl.abort(), timeoutMs)
      try {
        const res = await fetch(url, {
          method: 'POST',
          headers: { 'content-type': 'application/json' },
          body: JSON.stringify(obj),
          signal: ctl.signal
        })
        const text = await res.text()
        if (res.status !== 200) throw Object.assign(new Error(`vault desk answered HTTP ${res.status}: ${text.slice(0, 200)}`), { code: 'desk-http' })
        const body = JSON.parse(text)
        if (!Array.isArray(body?.replies)) throw Object.assign(new Error('vault desk answered without replies'), { code: 'desk-malformed' })
        for (const p of body.replies) emitir(p)
      } catch (e) {
        emitir({ type: 'vault.error', code: e.code || 'desk-unreachable', error: `vault desk ${url}: ${e.message}` })
      } finally {
        clearTimeout(t)
      }
    })()
  }

  return {
    desk: true,
    token: 'desk',
    send: (_to, obj) => enviar(obj),
    sendByPubkey: (_pub, obj) => enviar(obj),
    // Igual que en el mostrador local: la puerta la abre el cert de cada mensaje, y aquí no
    // hay a quién direccionar. Las dos formas, porque quien llama no sabe por dónde salió.
    identify: async () => ({ ok: true }),
    identifyAs: async () => ({ ok: true }),
    on: (ev, fn) => {
      if (ev !== 'message') return () => {}
      oyentes.add(fn)
      return () => oyentes.delete(fn)
    },
    close: () => { oyentes.clear() }
  }
}

export default { connectHttp, httpDeskUrl }
