/**
 * Store de SECRETOS de servicios (`secrets.json`, 0600, mismo dir 0700 que la
 * maestra — mismo dominio de confianza, y **cifrado en reposo** con la misma
 * clave ligada a la máquina que la identidad, ver `atrest.js`: son tokens y
 * llaves de producción, no pueden quedar en claro en el disco).
 *
 * DOS CAJONES, y esa es la razón de ser de este archivo:
 *
 *   · **Por scope** (`ns`) — un NAMESPACE de servicio (`proxy`, `geo`, `bots`…).
 *     Lo comparten TODOS los aparatos del perfil que sirven ese namespace: la
 *     llave de la API es la misma la corra quien la corra.
 *   · **Por aparato** (`dev`) — la llave es la del miembro (su `pub`), y solo la
 *     lee ESE aparato. Es donde va lo que cambia de máquina a máquina (el puerto,
 *     la URL pública, el nombre del nodo) sin partir el ns en uno por servidor.
 *
 * Al pedir el bundle se entregan MEZCLADOS y **manda el aparato**: lo suyo pisa
 * lo del scope. Es el orden que espera cualquiera que haya usado un `.env`
 * general y otro de la máquina — lo específico gana.
 *
 * Un cert `vault:secrets:<ns>` solo puede leer SU ns (y, dentro de él, solo lo
 * suyo propio: el cajón por aparato se indexa por la llave que firma la petición,
 * así que no hay forma de pedir el de otro).
 */
import path from 'node:path'
import { readJson, writeJson } from './paths.js'
import { atRestFor } from './atrest.js'
import { isValidSecretsNs } from './protocol.js'

const SCHEMA_VERSION = 2
const MAX_VALUE_LEN = 8 * 1024
const KEY_RE = /^[A-Z0-9_]{1,64}$/

export function openSecretsStore (dir) {
  const file = path.join(dir, 'secrets.json')
  const atRest = atRestFor(dir)
  let data = readJson(file, null, atRest)
  // v1 → v2: el cajón por scope se conserva tal cual; solo estrena el `dev`.
  if (data?.schemaVersion === 1 && data.ns) data = { schemaVersion: SCHEMA_VERSION, ns: data.ns, dev: {} }
  if (!data || data.schemaVersion !== SCHEMA_VERSION) {
    data = { schemaVersion: SCHEMA_VERSION, ns: {}, dev: {} }
  }
  if (!data.dev) data.dev = {}
  writeJson(file, data, atRest) // reescribe al abrir: cifra lo que venía en claro
  const save = () => writeJson(file, data, atRest)

  const assertNs = (ns) => {
    if (!isValidSecretsNs(ns)) throw new Error('invalid namespace (use [a-z0-9-]{1,32}, e.g. "proxy")')
  }
  const assertPub = (pub) => {
    if (typeof pub !== 'string' || !pub) throw new Error('device required (the member public key)')
  }
  const assertKeyValue = (key, value) => {
    if (!KEY_RE.test(String(key || ''))) throw new Error('invalid key (use UPPERCASE_WITH_UNDERSCORES, e.g. TURN_KEY_ID)')
    if (typeof value !== 'string' || !value) throw new Error('value must be a non-empty string')
    if (value.length > MAX_VALUE_LEN) throw new Error(`value too long (max ${MAX_VALUE_LEN})`)
  }

  /** Borra la rama si se quedó vacía: un scope (o un aparato) sin variables no existe. */
  const prune = (bag, k) => { if (bag[k] && Object.keys(bag[k]).length === 0) delete bag[k] }

  return {
    /**
     * El bundle que se le entrega a un servicio: lo del scope con lo del aparato
     * ENCIMA. Sin `devicePub` devuelve solo lo del scope (lo que ve una lista).
     */
    get (ns, devicePub = null) {
      assertNs(ns)
      return { ...(data.ns[ns] || {}), ...(devicePub ? (data.dev[devicePub] || {}) : {}) }
    },
    set (ns, key, value) {
      assertNs(ns)
      assertKeyValue(key, value)
      if (!data.ns[ns]) data.ns[ns] = {}
      data.ns[ns][key] = value
      save()
    },
    delete (ns, key) {
      assertNs(ns)
      const existed = !!(data.ns[ns] && key in data.ns[ns])
      if (existed) {
        delete data.ns[ns][key]
        prune(data.ns, ns)
        save()
      }
      return existed
    },
    /** Solo nombres (ns → [claves]), sin valores: para `secret list`. */
    list () {
      const out = {}
      for (const ns of Object.keys(data.ns)) out[ns] = Object.keys(data.ns[ns])
      return out
    },

    // --- cajón POR APARATO -------------------------------------------------
    /** Las variables propias de un aparato (objeto plano KEY→valor; {} si no hay). */
    getDevice (pub) {
      assertPub(pub)
      return { ...(data.dev[pub] || {}) }
    },
    setDevice (pub, key, value) {
      assertPub(pub)
      assertKeyValue(key, value)
      if (!data.dev[pub]) data.dev[pub] = {}
      data.dev[pub][key] = value
      save()
    },
    deleteDevice (pub, key) {
      assertPub(pub)
      const existed = !!(data.dev[pub] && key in data.dev[pub])
      if (existed) {
        delete data.dev[pub][key]
        prune(data.dev, pub)
        save()
      }
      return existed
    },
    /**
     * Se va un aparato, se van sus variables. Lo llama el vault al quitar un
     * miembro: dejarlas sería guardar la configuración de una llave que ya no
     * entra, y reaparecería sola si mañana se enrola otro aparato con esa llave.
     */
    forgetDevice (pub) {
      assertPub(pub)
      const keys = Object.keys(data.dev[pub] || {})
      if (keys.length) { delete data.dev[pub]; save() }
      return keys.length
    },
    /** Solo nombres (pub → [claves]), sin valores. */
    listDevices () {
      const out = {}
      for (const pub of Object.keys(data.dev)) out[pub] = Object.keys(data.dev[pub])
      return out
    }
  }
}
