/**
 * Store de SECRETOS de servicios (`secrets.json`, 0600, mismo dir 0700 que la
 * maestra), **cifrado en reposo** con la clave ligada a la máquina (`atrest.js`) y,
 * desde v4, con los valores privados **SELLADOS A SU DESTINATARIO**.
 *
 * QUÉ CAMBIA EN v4 Y POR QUÉ. Hasta v3 el valor se guardaba tal cual y el cifrado en
 * reposo era toda la defensa; como su material (`/etc/machine-id` + `atrest.salt`)
 * vive en ese mismo disco, una copia del disco lo entregaba todo. Eso importa porque
 * este daemon corre en una máquina alquilada. Ahora una variable privada se guarda
 * cifrada con la CEK de su cajón, y esa CEK va **envuelta a la llave de cifrado de
 * cada miembro** que deba leerla — nunca a la de esta bóveda. El vault reparte sobres
 * que no puede abrir. Diseño completo: `docs/secretos-sellados.md`.
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
 * general y otro de la máquina — lo específico gana. **La mezcla sigue aquí** y sigue
 * siendo una línea: los NOMBRES no se sellan, solo los valores, así que juntarlos no
 * exige poder leerlos. Quien descifra es el agente, después.
 *
 * CADA VARIABLE ES PÚBLICA O PRIVADA, y eso decide UNA cosa: si su VALOR puede
 * salir de esta máquina hacia la consola remota (`docs/consola-remota.md`). Al
 * servicio que la lee le da igual —recibe las dos—; lo que cambia es que el valor
 * de una privada no se le enseña a nadie más, ni siquiera a un aparato tuyo con
 * permiso de administrar. Se nace PRIVADA: enseñar un secreto tiene que ser una
 * decisión, no un descuido. **En v4 eso se vuelve literal**: la pública se guarda en
 * claro (para eso se marcó) y la privada es opaca hasta para esta bóveda.
 *
 * ESTE MÓDULO NO HACE CRIPTOGRAFÍA. Recibe un `sealer` (ver `src/sealer.js`) y le
 * pide sobres. Así se prueba con un sellador falso y determinista, y la forma del
 * archivo se razona sin mirar una sola llave.
 */
import path from 'node:path'
import { readJson, writeJson } from './paths.js'
import { atRestFor } from './atrest.js'
import { isValidSecretsNs } from './protocol.js'

const SCHEMA_VERSION = 4
const LEGACY_VERSION = 3
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

/** Se pidió una operación que necesita abrir la copia maestra, y no vino la llave. */
export class NeedsPassword extends Error {
  constructor (what) {
    super(`this needs the profile password: ${what}`)
    this.code = 'NEEDS_PASSWORD'
  }
}

/** Migra un cajón `{KEY: 'valor'}` (v1/v2) a `{KEY: {v, pub}}`: todo entra como PRIVADO. */
function migrateBag (bag) {
  const out = {}
  for (const [k, v] of Object.entries(bag || {})) out[k] = (v && typeof v === 'object') ? v : { v: v, pub: false }
  return out
}

/**
 * Abre el store.
 *
 * @param {string} dir
 * @param {{ sealer?: object, defaultKey?: () => Uint8Array }} [opts]
 *   `sealer`: el puerto de sobres (`src/sealer.js`). Sin él, el store solo sabe leer y
 *   servir lo que ya hay — que es exactamente lo que hace falta para arrancar sin
 *   contraseña.
 *   `defaultKey`: con qué abrir la copia maestra cuando el perfil NO tiene contraseña.
 *   Vive aquí, en un solo sitio, para que dé igual por qué puerta se entre a escribir.
 */
export function openSecretsStore (dir, { sealer = null, defaultKey = null } = {}) {
  const file = path.join(dir, 'secrets.json')
  const atRest = atRestFor(dir)
  let data = readJson(file, null, atRest)

  // v1 → v2: el cajón por scope se conserva y estrena el `dev`.
  // v2 → v3: los valores dejan de ser strings sueltos y pasan a llevar su visibilidad.
  //          Lo que ya existía entra como PRIVADO: nadie marcó nunca que se pudiera ver.
  if (data && data.schemaVersion > 0 && data.schemaVersion < LEGACY_VERSION) {
    const ns = {}; const dev = {}
    for (const [k, bag] of Object.entries(data.ns || {})) ns[k] = migrateBag(bag)
    for (const [k, bag] of Object.entries(data.dev || {})) dev[k] = migrateBag(bag)
    data = { schemaVersion: LEGACY_VERSION, ns, dev }
  }
  if (!data) data = { schemaVersion: SCHEMA_VERSION, ns: {}, dev: {}, master: null }
  if (!data.dev) data.dev = {}

  // v3 → v4 NO se hace al abrir, y es deliberado: sellar exige la contraseña, y el
  // daemon tiene que poder arrancar y SERVIR sin ella (un perfil bloqueado sigue
  // atendiendo a sus agentes). Así que un archivo v3 se queda en v3, sirviendo en
  // claro como hasta ahora, hasta que alguien administre estando desbloqueado. Hasta
  // entonces el despliegue se deshace con un reinicio, sin haber tocado los datos.
  const isLegacy = () => data.schemaVersion === LEGACY_VERSION

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
  const needSealer = (what) => { if (!sealer) throw new NeedsPassword(what) }
  /** La llave con la que abrir la copia maestra: la dada, o la del perfil sin contraseña. */
  const keyOr = (adminKey) => adminKey || defaultKey?.() || null

  /** Borra la rama si se quedó vacía: un scope (o un aparato) sin variables no existe. */
  const prune = (bag, k) => { if (bag[k] && Object.keys(bag[k]).length === 0) delete bag[k] }

  // --- forma de un cajón -------------------------------------------------------
  // v3: `bag[k]` ES el mapa de variables. v4: `bag[k] = { vars, keyring }`.
  // `varsOf` es el único sitio que conoce las dos, para que el resto del archivo
  // hable de variables y no de versiones.
  const varsOf = (bag, k) => (isLegacy() ? (bag[k] || {}) : (bag[k]?.vars || {}))
  const ensureBag = (bag, k) => {
    if (isLegacy()) { if (!bag[k]) bag[k] = {}; return bag[k] }
    if (!bag[k]) bag[k] = { vars: {}, keyring: [] }
    if (!bag[k].vars) bag[k].vars = {}
    if (!bag[k].keyring) bag[k].keyring = []
    return bag[k].vars
  }

  /** Los NOMBRES con su visibilidad: es lo que ve cualquier lista. Nunca valores. */
  const names = (bag, k) => Object.entries(varsOf(bag, k)).map(([key, e]) => ({ key, public: !!e.pub }))
  /** Solo las PÚBLICAS, con valor: lo único que puede salir hacia la consola remota. */
  const publics = (bag, k) => Object.fromEntries(
    Object.entries(varsOf(bag, k)).filter(([, e]) => e.pub).map(([key, e]) => [key, e.v])
  )
  /**
   * Las entradas TAL CUAL van al bundle: la pública con su valor, la privada con su
   * sobre. No se descifra nada aquí — de eso vive todo esto.
   */
  const entriesOf = (bag, k) => ({ ...varsOf(bag, k) })

  /** La generación vigente del llavero de un cajón (la de `gen` mayor). */
  const topGen = (bag, k) => {
    const kr = bag[k]?.keyring || []
    return kr.reduce((best, g) => (!best || (g.gen || 0) > (best.gen || 0) ? g : best), null)
  }

  return {
    /** `true` mientras el archivo siga en v3 (sin sellar), a la espera del primer desbloqueo. */
    isLegacy,
    schemaVersion: () => data.schemaVersion,

    /**
     * MUCHAS ESCRITURAS, UN GUARDADO. Cargar la configuración de un servicio son veinte
     * variables pero un solo cambio: con un `save()` por variable, el archivo entero se
     * reescribía y se volvía a cifrar veinte veces.
     *
     * Desde v4 acepta una `fn` ASÍNCRONA, porque sellar lo es. El contrato es el mismo:
     * el grupo se cierra cuando `fn` termina, y si lanza a la mitad se guarda lo que ya
     * se hubiera tocado — igual que escribiendo de una en una. Quien llama valida ANTES
     * para que no ocurra.
     */
    async batch (fn) {
      held++
      try { return await fn() } finally {
        held--
        if (!held && pending) { pending = false; flush() }
      }
    },

    /**
     * El bundle que se le entrega a un servicio: lo del scope con lo del aparato
     * ENCIMA. Públicas y privadas por igual — la visibilidad no es un permiso de
     * lectura del servicio, es si el valor puede salir de esta máquina.
     *
     * Devuelve las entradas SIN abrir, más la envoltura de la CEK **de este miembro y
     * solo la suya**: el resto del llavero son las llaves de sus compañeros y no le
     * hacen falta. En v3 devuelve los valores en claro, como siempre.
     */
    bundleFor (ns, devicePub = null) {
      assertNs(ns)
      const entries = { ...entriesOf(data.ns, ns), ...(devicePub ? entriesOf(data.dev, devicePub) : {}) }
      if (isLegacy()) return { legacy: true, entries }
      const wrapOf = (bag, k) => {
        const g = topGen(bag, k)
        const w = g?.wraps?.[devicePub]
        return w ? { gen: g.gen, wrap: w } : null
      }
      return { entries, ns: wrapOf(data.ns, ns), dev: devicePub ? wrapOf(data.dev, devicePub) : null }
    },

    /**
     * Igual que `bundleFor` pero YA ABIERTO. Solo existe para las pruebas y para
     * diagnosticar: pide la contraseña, y si el archivo es v4 sin sellador disponible
     * no puede hacer nada. Nadie del camino de servir lo llama.
     */
    async openBundle (ns, devicePub = null, adminKey = null) {
      const b = this.bundleFor(ns, devicePub)
      if (b.legacy) return Object.fromEntries(Object.entries(b.entries).map(([k, e]) => [k, e.v]))
      needSealer('read the values of a sealed store')
      const master = await sealer.openMaster(data.master, keyOr(adminKey))
      const out = {}
      for (const [key, e] of Object.entries(b.entries)) {
        out[key] = e.pub ? e.v : await sealer.decrypt(master, e.e, e.owner)
      }
      return out
    },

    // --- escritura (sella, así que necesita la copia maestra) --------------------
    /**
     * Escribe en un cajón. `isPublic` es OPCIONAL a propósito: sin decir nada se
     * conserva lo que la variable ya era (rotar un valor no debe cambiar quién puede
     * verlo por olvido) y una variable nueva nace PRIVADA.
     */
    async set (ns, key, value, isPublic, adminKey = null) {
      assertNs(ns)
      return this._put(data.ns, ns, `ns:${ns}`, key, value, isPublic, adminKey)
    },
    async setDevice (pub, key, value, isPublic, adminKey = null) {
      assertPub(pub)
      return this._put(data.dev, pub, `dev:${pub}`, key, value, isPublic, adminKey)
    },

    /** @private Común a los dos cajones: la única diferencia es de dónde sale la CEK. */
    async _put (bag, k, owner, key, value, isPublic, adminKey) {
      assertKeyValue(key, value)
      const vars = ensureBag(bag, k)
      const before = vars[key]
      const pub = isPublic === undefined ? !!before?.pub : !!isPublic

      // v3: se guarda como siempre. La migración a sobres es un gesto aparte y
      // explícito (`migrate`), no algo que ocurra de refilón al escribir.
      if (isLegacy()) { vars[key] = { v: value, pub }; save(); return }

      // Una PÚBLICA se guarda en claro a propósito: eso es lo que significa marcarla.
      if (pub) { vars[key] = { v: value, pub: true }; save(); return }

      needSealer('write a private variable')
      const master = await sealer.openMaster(data.master, keyOr(adminKey))
      const cek = await sealer.cekFor(master, owner)
      vars[key] = { pub: false, owner, e: await sealer.encrypt(cek, value) }
      data.master = await sealer.sealMaster(master, keyOr(adminKey))
      save()
    },

    async delete (ns, key) {
      assertNs(ns)
      return this._drop(data.ns, ns, key)
    },
    async deleteDevice (pub, key) {
      assertPub(pub)
      return this._drop(data.dev, pub, key)
    },
    /** @private Borrar NO exige contraseña: quitar algo no pide poder leerlo. */
    _drop (bag, k, key) {
      const vars = varsOf(bag, k)
      const existed = key in vars
      if (!existed) return false
      delete vars[key]
      if (Object.keys(vars).length === 0) prune(bag, k)
      save()
      return true
    },

    /**
     * Cambia SOLO la visibilidad, sin tocar el valor. Existe porque, si no, hacer pública
     * una variable obligaría a volver a teclear el secreto — y quien la marca casi nunca lo
     * tiene a mano.
     *
     * Ojo: de PRIVADA a PÚBLICA hay que descifrar para poder guardarla en claro, así que
     * ese sentido sí pide la contraseña. Al revés (pública → privada) también, porque hay
     * que sellarla. No hay forma de esquivarlo: es literalmente cambiar de forma el dato.
     */
    async setVisibility (ns, key, isPublic, adminKey = null) {
      assertNs(ns)
      return this._setVis(data.ns, ns, `ns:${ns}`, key, isPublic, adminKey)
    },
    async setDeviceVisibility (pub, key, isPublic, adminKey = null) {
      assertPub(pub)
      return this._setVis(data.dev, pub, `dev:${pub}`, key, isPublic, adminKey)
    },
    /** @private */
    async _setVis (bag, k, owner, key, isPublic, adminKey) {
      const vars = varsOf(bag, k)
      const e = vars[key]
      if (!e) return false
      const want = !!isPublic
      if (isLegacy()) { e.pub = want; save(); return true }
      if (!!e.pub === want) return true

      needSealer('change the visibility of a variable')
      const master = await sealer.openMaster(data.master, keyOr(adminKey))
      const value = e.pub ? e.v : await sealer.decrypt(master, e.e, e.owner)
      if (want) {
        vars[key] = { v: value, pub: true }
      } else {
        const cek = await sealer.cekFor(master, owner)
        vars[key] = { pub: false, owner, e: await sealer.encrypt(cek, value) }
      }
      data.master = await sealer.sealMaster(master, keyOr(adminKey))
      save()
      return true
    },

    // --- lecturas que NO abren nada ---------------------------------------------
    /** Nombres y visibilidad (ns → [{key, public}]), sin valores: para `secret list`. */
    list () {
      const out = {}
      for (const ns of Object.keys(data.ns)) out[ns] = names(data.ns, ns)
      return out
    },
    /** Nombres y visibilidad (pub → [{key, public}]), sin valores. */
    listDevices () {
      const out = {}
      for (const pub of Object.keys(data.dev)) out[pub] = names(data.dev, pub)
      return out
    },
    /** Las PÚBLICAS de un scope, con valor. Lo que la consola remota puede ver. */
    publicOf (ns) {
      assertNs(ns)
      return publics(data.ns, ns)
    },
    /** Las PÚBLICAS de un aparato, con valor. */
    publicOfDevice (pub) {
      assertPub(pub)
      return publics(data.dev, pub)
    },

    // --- llavero: quién puede abrir cada cajón ----------------------------------
    /**
     * Re-envuelve la CEK de un cajón a los miembros dados. Es lo que hay que llamar
     * cuando entra un aparato nuevo a un ns que ya tiene variables — si no, recibe los
     * sobres y no puede abrir ninguno.
     *
     * Los miembros sin llave de cifrado se devuelven en `sinLlave` en vez de fallar:
     * quien administra tiene que poder VERLO, porque el síntoma sería un servicio que
     * arranca sin configuración y no dice por qué.
     */
    async rewrap (owner, members, adminKey = null) {
      needSealer('re-wrap the key of a drawer')
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      if (!bag[k]) return { wrapped: 0, sinLlave: [] }
      const master = await sealer.openMaster(data.master, keyOr(adminKey))
      const cek = await sealer.cekFor(master, owner)
      const gen = (topGen(bag, k)?.gen || 0) || 1
      const { wraps, sinLlave } = await sealer.wrapFor(cek, members)
      bag[k].keyring = [{ gen, createdAt: Date.now(), wraps }]
      data.master = await sealer.sealMaster(master, keyOr(adminKey))
      save()
      return { wrapped: Object.keys(wraps).length, sinLlave }
    },

    /**
     * ROTA la CEK de un cajón: genera una nueva, vuelve a cifrar sus variables privadas
     * y la envuelve solo a los miembros dados. Es lo que corta de verdad el acceso de
     * quien salió — quitarle la envoltura no basta, porque si guardó la CEK sigue
     * abriendo todo lo cifrado con ella.
     *
     * No devuelve lo que el expulsado ya leyó. Eso no se puede deshacer y no se promete.
     */
    async rotate (owner, members, adminKey = null) {
      needSealer('rotate the key of a drawer')
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      if (!bag[k]) return { rotated: 0, sinLlave: [] }
      const master = await sealer.openMaster(data.master, keyOr(adminKey))
      const vieja = await sealer.cekFor(master, owner)

      const vars = bag[k].vars || {}
      const claras = {}
      for (const [key, e] of Object.entries(vars)) {
        if (!e.pub) claras[key] = await sealer.decrypt(master, e.e, e.owner)
      }
      const nueva = await sealer.newCek(master, owner)
      for (const [key, value] of Object.entries(claras)) {
        vars[key] = { pub: false, owner, e: await sealer.encrypt(nueva, value) }
      }
      const gen = (topGen(bag, k)?.gen || 0) + 1
      const { wraps, sinLlave } = await sealer.wrapFor(nueva, members)
      bag[k].keyring = [{ gen, createdAt: Date.now(), wraps }]
      data.master = await sealer.sealMaster(master, keyOr(adminKey))
      save()
      return { rotated: Object.keys(claras).length, sinLlave, gen, cambio: vieja !== nueva }
    },

    /**
     * Se va un aparato, se van sus variables. Lo llama el vault al quitar un
     * miembro: dejarlas sería guardar la configuración de una llave que ya no
     * entra, y reaparecería sola si mañana se enrola otro aparato con esa llave.
     *
     * NO exige contraseña: es la mitad del interruptor de emergencia, y un interruptor
     * de emergencia que pide una frase que quizá no tienes a mano no sirve. Su cajón
     * `dev` estaba sellado solo a él, así que borrarlo es inmediato y completo. Lo que
     * sí queda pendiente es rotar los `ns` que compartía (ver `rotate`).
     */
    forgetDevice (pub) {
      assertPub(pub)
      const keys = Object.keys(varsOf(data.dev, pub))
      if (keys.length || data.dev[pub]) { delete data.dev[pub]; save() }
      return keys.length
    },

    /**
     * Vuelve a cerrar la copia maestra con OTRA llave. Es lo que hay que hacer al
     * cambiar (o quitar) la contraseña del perfil: los sobres de las variables no se
     * tocan —siguen cifrados con la CEK de su cajón—, lo único que cambia es con qué
     * se abre el llavero de administración.
     *
     * Sin esto, cambiar la contraseña dejaría los secretos ILEGIBLES: la copia maestra
     * seguiría sellada con la llave vieja y ya nadie tendría cómo abrirla. Es barato
     * (un solo sobre) y es obligatorio.
     *
     * `null` en cualquiera de las dos significa «la del perfil sin contraseña».
     */
    async rekeyMaster (oldKey, newKey) {
      if (isLegacy()) return { rekeyed: false, reason: 'v3' }
      needSealer('change the profile password')
      const master = await sealer.openMaster(data.master, keyOr(oldKey))
      data.master = await sealer.sealMaster(master, keyOr(newKey))
      save()
      return { rekeyed: true, drawers: Object.keys(master).length }
    },

    // --- migración v3 → v4 -------------------------------------------------------
    /**
     * Sella un archivo v3 entero. Corre en el PRIMER desbloqueo administrativo, no al
     * abrir, porque necesita la contraseña.
     *
     * Verificar antes de reemplazar, igual que `migrateFile()` de `atrest.js`: se
     * construye la forma nueva, se vuelve a abrir **valor por valor** y se compara con
     * el original, y solo entonces se escribe. Si algo no cuadra no se toca nada y se
     * lanza: media migración es peor que ninguna.
     *
     * `membersOf(owner)` dice a quién hay que envolverle la CEK de cada cajón.
     */
    async migrate (membersOf, adminKey = null) {
      if (!isLegacy()) return { migrated: false, reason: 'already-v4' }
      needSealer('seal the store')

      const antes = {}
      const next = { schemaVersion: SCHEMA_VERSION, ns: {}, dev: {}, master: null }
      let master = await sealer.openMaster(null, keyOr(adminKey))
      const sinLlave = {}

      for (const [kind, src, dst] of [['ns', data.ns, next.ns], ['dev', data.dev, next.dev]]) {
        for (const [k, bag] of Object.entries(src)) {
          const owner = `${kind}:${k}`
          const cek = await sealer.newCek(master, owner)
          const vars = {}
          for (const [key, e] of Object.entries(bag || {})) {
            antes[`${owner}\u0000${key}`] = e.v
            vars[key] = e.pub ? { v: e.v, pub: true } : { pub: false, owner, e: await sealer.encrypt(cek, e.v) }
          }
          const { wraps, sinLlave: faltan } = await sealer.wrapFor(cek, membersOf(owner) || [])
          if (faltan.length) sinLlave[owner] = faltan
          dst[k] = { vars, keyring: [{ gen: 1, createdAt: Date.now(), wraps }] }
        }
      }
      next.master = await sealer.sealMaster(master, keyOr(adminKey))

      // Releer lo escrito y comparar contra el original, antes de reemplazar nada.
      master = await sealer.openMaster(next.master, keyOr(adminKey))
      for (const [kind, dst] of [['ns', next.ns], ['dev', next.dev]]) {
        for (const [k, bag] of Object.entries(dst)) {
          const owner = `${kind}:${k}`
          for (const [key, e] of Object.entries(bag.vars)) {
            const abierto = e.pub ? e.v : await sealer.decrypt(master, e.e, e.owner)
            if (abierto !== antes[`${owner}\u0000${key}`]) {
              throw new Error(`secrets: the migration check failed on ${owner}/${key}; nothing was touched`)
            }
          }
        }
      }

      // Copia del v3 antes de pisarlo. Con nodos en producción, deshacer tiene que ser
      // un `mv`, no una restauración. La borra el operador a mano.
      writeJson(file + '.v3.bak', data, atRest)
      data = next
      flush()
      return { migrated: true, sinLlave }
    }
  }
}

/** `ns:proxy` → `['ns','proxy']`. El `dev:` lleva dentro un JWK con dos puntos. */
function splitOwner (owner) {
  const i = String(owner).indexOf(':')
  if (i < 0) throw new Error('invalid drawer: expected "ns:<name>" or "dev:<pubkey>"')
  return [owner.slice(0, i), owner.slice(i + 1)]
}
