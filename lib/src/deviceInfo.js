/**
 * deviceInfo.js — QUÉ APARATO SOY, dicho igual en todos los comandos del ecosistema.
 *
 * Regla del dueño (2026-09-29): todo comando que se enrola en una bóveda tiene un `info`
 * que enseña la información del aparato, **sobre todo su id**. El id (`AB12-CD34`) es lo que
 * sale en `dotrino-vault members` y lo que pide `dotrino-vault caps <ID>`: sin verlo aquí no
 * hay forma de saber qué fila del acta es esta máquina. `dotrino-env status` enseñaba la
 * llave de la bóveda en crudo (`{"key_ops":["verify"],…`) y ningún id.
 *
 * Una sola pieza para todos: `dotrino-env`, los agentes de remote-agent (terminal, ia) y lo
 * que venga. Local y sin red: lee el enlace que ya está en el disco, así que responde con
 * la bóveda apagada, que es justo cuando más falta hace saber quién eres.
 *
 * Sirve cualquier enlace con la forma común `{ device: { publickey }, cert, iss, proxy }`
 * (el de remote-agent y el de un servicio de dotrino-env).
 */
import { pubkeyId } from '@dotrino/identity/capabilities'

/** El id corto de una llave, como lo enseña la bóveda: `AB12-CD34`. */
export async function shortId (publickey) {
  return (await pubkeyId(publickey)).slice(0, 8).toUpperCase().replace(/(.{4})(.{4})/, '$1-$2')
}

/**
 * La información del aparato a partir de su enlace.
 * @param {{ device?: { publickey?: string }, cert?: object, iss?: string, proxy?: string }} link
 * @param {Record<string, any>} [extra]  lo propio de cada comando (nombre, versión, carpeta…).
 */
export async function deviceInfo (link, extra = {}) {
  const pub = link?.device?.publickey
  if (!pub) throw Object.assign(new Error('this link has no device key: enroll first'), { code: 'not-enrolled' })
  const cert = link.cert || null
  return {
    id: await shortId(pub),
    vault: link.iss ? await shortId(link.iss) : null,
    scope: Array.isArray(cert?.scope) ? cert.scope : [],
    // El papel se describe por el acta a la que se ató; uno del modelo viejo, por su fecha,
    // porque eso sí importa: es lo único que todavía caduca.
    record: typeof cert?.seq === 'number' ? cert.seq : null,
    legacyExpires: typeof cert?.seq !== 'number' && typeof cert?.exp === 'number' ? cert.exp : null,
    proxy: link.proxy || null,
    publickey: pub,
    ...extra
  }
}

const LABELS = {
  id: 'Aparato', vault: 'Bóveda', kind: 'Tipo', name: 'Nombre', ns: 'Cajón', version: 'Versión',
  scope: 'Permisos', record: 'Papel', dir: 'Enlace', proxy: 'Proxio'
}

/**
 * El texto que imprime `info`. El id va primero y con la pista de dónde buscarlo: es lo que
 * se viene a mirar.
 * @param {Awaited<ReturnType<typeof deviceInfo>>} info
 */
export function formatDeviceInfo (info) {
  const rows = []
  const put = (k, v) => { if (v != null && v !== '') rows.push([LABELS[k] || k, v]) }
  put('id', `${info.id}   (así sale en \`dotrino-vault members\`)`)
  put('vault', info.vault)
  put('kind', info.kind); put('name', info.name); put('ns', info.ns); put('version', info.version)
  put('scope', info.scope?.length ? info.scope.join(', ') : null)
  put('record', info.record != null
    ? `acta #${info.record}`
    : (info.legacyExpires ? `modelo viejo, vence ${new Date(info.legacyExpires).toISOString().slice(0, 10)}` : null))
  put('dir', info.dir); put('proxy', info.proxy)
  const w = Math.max(...rows.map(([k]) => k.length))
  return rows.map(([k, v]) => `${(k + ':').padEnd(w + 2)}${v}`).join('\n')
}
