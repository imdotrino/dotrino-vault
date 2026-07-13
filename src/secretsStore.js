/**
 * Store de SECRETOS de servicios (`secrets.json`, 0600, mismo dir 0700 que la
 * maestra — mismo dominio de confianza, v1 en claro en reposo igual que
 * `identity.json`; el cifrado en reposo con contraseña llega con v2 para todo
 * el dir). Organizado por NAMESPACE de servicio (`proxy`, `geo`, `bots`…):
 * un cert `vault:secrets:<ns>` solo puede leer SU ns.
 */
import path from 'node:path'
import { readJson, writeJson } from './paths.js'
import { isValidSecretsNs } from './protocol.js'

const SCHEMA_VERSION = 1
const MAX_VALUE_LEN = 8 * 1024
const KEY_RE = /^[A-Z0-9_]{1,64}$/

export function openSecretsStore (dir) {
  const file = path.join(dir, 'secrets.json')
  let data = readJson(file, null)
  if (!data || data.schemaVersion !== SCHEMA_VERSION) {
    data = { schemaVersion: SCHEMA_VERSION, ns: {} }
    writeJson(file, data)
  }
  const save = () => writeJson(file, data)

  const assertNs = (ns) => {
    if (!isValidSecretsNs(ns)) throw new Error('namespace inválido (usa [a-z0-9-]{1,32}, p.ej. "proxy")')
  }

  return {
    /** Secretos de un ns (objeto plano KEY→valor; {} si no hay). */
    get (ns) {
      assertNs(ns)
      return { ...(data.ns[ns] || {}) }
    },
    set (ns, key, value) {
      assertNs(ns)
      if (!KEY_RE.test(String(key || ''))) throw new Error('clave inválida (usa MAYUSCULAS_CON_GUION_BAJO, p.ej. TURN_KEY_ID)')
      if (typeof value !== 'string' || !value) throw new Error('el valor debe ser un string no vacío')
      if (value.length > MAX_VALUE_LEN) throw new Error(`valor demasiado largo (máx ${MAX_VALUE_LEN})`)
      if (!data.ns[ns]) data.ns[ns] = {}
      data.ns[ns][key] = value
      save()
    },
    delete (ns, key) {
      assertNs(ns)
      const existed = !!(data.ns[ns] && key in data.ns[ns])
      if (existed) {
        delete data.ns[ns][key]
        if (Object.keys(data.ns[ns]).length === 0) delete data.ns[ns]
        save()
      }
      return existed
    },
    /** Solo nombres (ns → [claves]), sin valores: para `secret list`. */
    list () {
      const out = {}
      for (const ns of Object.keys(data.ns)) out[ns] = Object.keys(data.ns[ns])
      return out
    }
  }
}
