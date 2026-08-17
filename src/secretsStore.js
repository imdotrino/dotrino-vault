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
 *
 * CADA VARIABLE ES PÚBLICA O PRIVADA, y eso decide UNA cosa: si su VALOR puede
 * salir de esta máquina hacia la consola remota (`docs/consola-remota.md`). Al
 * servicio que la lee le da igual —recibe las dos—; lo que cambia es que el valor
 * de una privada no se le enseña a nadie más, ni siquiera a un aparato tuyo con
 * permiso de administrar. Se nace PRIVADA: enseñar un secreto tiene que ser una
 * decisión, no un descuido.
 */
import path from 'node:path'
import { readJson, writeJson } from './paths.js'
import { atRestFor } from './atrest.js'
import { isValidSecretsNs } from './protocol.js'

const SCHEMA_VERSION = 3
const MAX_VALUE_LEN = 8 * 1024
const KEY_RE = /^[A-Z0-9_]{1,64}$/

/**
 * Valida un par nombre/valor. Se exporta porque quien carga varias variables de golpe
 * las comprueba TODAS antes de escribir ninguna: media configuración aplicada y un
 * error a la mitad es justo lo que la carga en grupo viene a evitar.
 */
export function assertVar (key, value) {
  if (!KEY_RE.test(String(key || ''))) throw new Error('invalid key (use UPPERCASE_WITH_UNDERSCORES, e.g. TURN_KEY_ID)')
  if (typeof value !== 'string' || !value) throw new Error('value must be a non-empty string')
  if (value.length > MAX_VALUE_LEN) throw new Error(`value too long (max ${MAX_VALUE_LEN})`)
}

/** Una variable guardada: `{ v: valor, pub: ¿la puede ver la consola? }`. */
const entry = (value, isPublic) => ({ v: value, pub: !!isPublic })

/** Migra un cajón `{KEY: 'valor'}` (v1/v2) a `{KEY: {v, pub}}`: todo entra como PRIVADO. */
function migrateBag (bag) {
  const out = {}
  for (const [k, v] of Object.entries(bag || {})) out[k] = (v && typeof v === 'object') ? v : entry(v, false)
  return out
}

export function openSecretsStore (dir) {
  const file = path.join(dir, 'secrets.json')
  const atRest = atRestFor(dir)
  let data = readJson(file, null, atRest)
  // v1 → v2: el cajón por scope se conserva y estrena el `dev`.
  // v2 → v3: los valores dejan de ser strings sueltos y pasan a llevar su visibilidad.
  //          Lo que ya existía entra como PRIVADO: nadie marcó nunca que se pudiera ver.
  if (data && data.schemaVersion > 0 && data.schemaVersion < SCHEMA_VERSION) {
    const ns = {}; const dev = {}
    for (const [k, bag] of Object.entries(data.ns || {})) ns[k] = migrateBag(bag)
    for (const [k, bag] of Object.entries(data.dev || {})) dev[k] = migrateBag(bag)
    data = { schemaVersion: SCHEMA_VERSION, ns, dev }
  }
  if (!data || data.schemaVersion !== SCHEMA_VERSION) {
    data = { schemaVersion: SCHEMA_VERSION, ns: {}, dev: {} }
  }
  if (!data.dev) data.dev = {}
  writeJson(file, data, atRest) // reescribe al abrir: cifra lo que venía en claro

  // Un grupo de escrituras se guarda UNA vez (ver `batch`). Fuera de un grupo, `held`
  // vale 0 y cada cambio va al disco en el acto, como siempre.
  let held = 0
  let pending = false
  const flush = () => writeJson(file, data, atRest)
  const save = () => { if (held) { pending = true; return } ; flush() }

  const assertNs = (ns) => {
    if (!isValidSecretsNs(ns)) throw new Error('invalid namespace (use [a-z0-9-]{1,32}, e.g. "proxy")')
  }
  const assertPub = (pub) => {
    if (typeof pub !== 'string' || !pub) throw new Error('device required (the member public key)')
  }
  const assertKeyValue = assertVar

  /** Borra la rama si se quedó vacía: un scope (o un aparato) sin variables no existe. */
  const prune = (bag, k) => { if (bag[k] && Object.keys(bag[k]).length === 0) delete bag[k] }

  /** KEY→valor, sin la visibilidad: es lo que consume un servicio. */
  const plain = (bag) => Object.fromEntries(Object.entries(bag || {}).map(([k, e]) => [k, e.v]))
  /** Los NOMBRES con su visibilidad: es lo que ve cualquier lista. Nunca valores. */
  const names = (bag) => Object.entries(bag || {}).map(([k, e]) => ({ key: k, public: !!e.pub }))
  /** Solo las PÚBLICAS, con valor: lo único que puede salir hacia la consola remota. */
  const publics = (bag) => Object.fromEntries(
    Object.entries(bag || {}).filter(([, e]) => e.pub).map(([k, e]) => [k, e.v])
  )

  /**
   * Escribe en un cajón. `isPublic` es OPCIONAL a propósito: sin decir nada se
   * conserva lo que la variable ya era (rotar un valor no debe cambiar quién puede
   * verlo por olvido) y una variable nueva nace PRIVADA.
   */
  const put = (bag, k, key, value, isPublic) => {
    assertKeyValue(key, value)
    if (!bag[k]) bag[k] = {}
    const before = bag[k][key]
    bag[k][key] = entry(value, isPublic === undefined ? !!before?.pub : isPublic)
    save()
  }

  /**
   * Cambia SOLO la visibilidad, sin tocar el valor. Existe porque, si no, hacer pública
   * una variable obligaría a volver a teclear el secreto — y quien la marca casi nunca lo
   * tiene a mano.
   */
  const setVis = (bag, k, key, isPublic) => {
    const e = bag[k]?.[key]
    if (!e) return false
    e.pub = !!isPublic
    save()
    return true
  }

  const drop = (bag, k, key) => {
    const existed = !!(bag[k] && key in bag[k])
    if (existed) { delete bag[k][key]; prune(bag, k); save() }
    return existed
  }

  return {
    /**
     * MUCHAS ESCRITURAS, UN GUARDADO. Cargar la configuración de un servicio son veinte
     * variables pero un solo cambio: con un `save()` por variable, el archivo entero se
     * reescribía y se volvía a cifrar veinte veces.
     *
     * Solo síncrono: `fn` no puede esperar nada, porque el grupo se cierra al volver.
     * Si `fn` lanza a la mitad se guarda igual lo que ya había tocado — es lo mismo que
     * pasaba escribiendo de una en una, y quien llama valida ANTES para que no ocurra.
     */
    batch (fn) {
      held++
      try { return fn() } finally {
        held--
        if (!held && pending) { pending = false; flush() }
      }
    },
    /**
     * El bundle que se le entrega a un servicio: lo del scope con lo del aparato
     * ENCIMA. Públicas y privadas por igual — la visibilidad no es un permiso de
     * lectura del servicio, es si el valor puede salir de esta máquina.
     */
    get (ns, devicePub = null) {
      assertNs(ns)
      return { ...plain(data.ns[ns]), ...(devicePub ? plain(data.dev[devicePub]) : {}) }
    },
    set (ns, key, value, isPublic) {
      assertNs(ns)
      put(data.ns, ns, key, value, isPublic)
    },
    delete (ns, key) {
      assertNs(ns)
      return drop(data.ns, ns, key)
    },
    /** Nombres y visibilidad (ns → [{key, public}]), sin valores: para `secret list`. */
    list () {
      const out = {}
      for (const ns of Object.keys(data.ns)) out[ns] = names(data.ns[ns])
      return out
    },
    setVisibility (ns, key, isPublic) {
      assertNs(ns)
      return setVis(data.ns, ns, key, isPublic)
    },
    /** Las PÚBLICAS de un scope, con valor. Lo que la consola remota puede ver. */
    publicOf (ns) {
      assertNs(ns)
      return publics(data.ns[ns])
    },

    // --- cajón POR APARATO -------------------------------------------------
    /** Las variables propias de un aparato (KEY→valor; {} si no hay). */
    getDevice (pub) {
      assertPub(pub)
      return plain(data.dev[pub])
    },
    setDevice (pub, key, value, isPublic) {
      assertPub(pub)
      put(data.dev, pub, key, value, isPublic)
    },
    deleteDevice (pub, key) {
      assertPub(pub)
      return drop(data.dev, pub, key)
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
    setDeviceVisibility (pub, key, isPublic) {
      assertPub(pub)
      return setVis(data.dev, pub, key, isPublic)
    },
    /** Nombres y visibilidad (pub → [{key, public}]), sin valores. */
    listDevices () {
      const out = {}
      for (const pub of Object.keys(data.dev)) out[pub] = names(data.dev[pub])
      return out
    },
    /** Las PÚBLICAS de un aparato, con valor. */
    publicOfDevice (pub) {
      assertPub(pub)
      return publics(data.dev[pub])
    }
  }
}
