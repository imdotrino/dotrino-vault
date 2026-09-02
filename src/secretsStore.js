/**
 * Store de SECRETOS de servicios (`secrets.json`, 0600, mismo dir 0700 que la
 * maestra), **cifrado en reposo** con la clave ligada a la máquina (`atrest.js`) y,
 * desde v4, con los valores privados **SELLADOS A SU DESTINATARIO**.
 *
 * QUÉ CAMBIA EN v5 Y POR QUÉ: **ESCRIBIR NO PIDE LA FRASE**. Cifrar es una capacidad
 * pública —envolver una llave solo necesita la `encPub` del que va a leer— así que
 * sellar una variable nunca necesitó la contraseña. Lo que la pedía era la COPIA
 * MAESTRA de v4, que guardaba las CEK cifradas con ella; para escribir había que
 * abrirla, y eso obligaba a teclear la frase del perfil en el navegador. Aquí se va la
 * copia maestra y en su lugar entra un **par de recuperación**: su pública se guarda en
 * claro (cualquiera puede envolverle) y su privada, sellada bajo la frase (solo el
 * dueño abre). Diseño completo: `docs/secretos-sellados.md` §8.
 *
 * De ahí salen las tres reglas de este archivo:
 *
 *   · **Escribir** = CEK nueva → envolverla a los destinatarios → cifrar → firmar.
 *     Ningún secreto de la bóveda interviene.
 *   · **UNA GENERACIÓN POR ESCRITURA**, y no es un capricho: la bóveda no puede
 *     reutilizar la CEK del cajón porque no puede abrir ninguna envoltura para
 *     recuperarla. Las generaciones que ya no referencia ningún valor ni el histórico
 *     se recogen solas.
 *   · **Leer** (ver un valor, cambiar su visibilidad, rotar re-cifrando) sigue pidiendo
 *     la frase, porque leer es exactamente lo que la frase guarda.
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
 * de una privada no se le enseña a nadie más. Se nace PRIVADA: enseñar un secreto
 * tiene que ser una decisión, no un descuido.
 *
 * EL HISTÓRICO. Cada escritura guarda el sobre ANTERIOR, con quién y cuándo. La bóveda
 * lo escribe sin poder leerlo; auditar y revertir los hace quien puede abrir. Tiene
 * tope: un histórico de secretos también es un pasivo — mantiene vivas credenciales
 * viejas — así que se poda.
 *
 * ESTE MÓDULO NO HACE CRIPTOGRAFÍA. Recibe un `sealer` (ver `src/sealer.js`) y le
 * pide sobres. Así se prueba con un sellador falso y determinista, y la forma del
 * archivo se razona sin mirar una sola llave.
 */
import path from 'node:path'
import { readJson, writeJson } from './paths.js'
import { atRestFor } from './atrest.js'
import { isValidSecretsNs } from './protocol.js'

const SCHEMA_VERSION = 5
/** v4: sellado, pero con la copia maestra bajo la frase. Se lee y se sirve; no se escribe. */
const SEALED_MASTER_VERSION = 4
const LEGACY_VERSION = 3
const MAX_VALUE_LEN = 8 * 1024
const KEY_RE = /^[A-Z0-9_]{1,64}$/

/**
 * La envoltura de la copia de RECUPERACIÓN va en el llavero como una más, con este
 * nombre en lugar de la pubkey de un miembro. No es un miembro y no debe parecerlo: el
 * acta no lo conoce y nadie le sirve un bundle.
 */
export const RECOVERY = '#recovery'

/** Cuántas versiones anteriores se conservan, en total. Ver «EL HISTÓRICO» arriba. */
const MAX_HISTORY = 500

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

/** Se pidió una operación que necesita LEER un valor, y no vino la llave que lo abre. */
export class NeedsPassword extends Error {
  constructor (what) {
    super(`this needs the profile password: ${what}`)
    this.code = 'NEEDS_PASSWORD'
  }
}

/**
 * El archivo sigue en v4 (con copia maestra) y hay que convertirlo antes de escribir.
 * Convertir exige la frase UNA vez —hay que abrir la maestra para poder re-sellar—, y a
 * partir de ahí no se pide nunca más para escribir.
 */
export class NeedsMigration extends Error {
  constructor () {
    super('the secrets file is still v4: unlock the profile once to convert it (it needs the password only this time)')
    this.code = 'NEEDS_MIGRATION'
  }
}

/**
 * Privada es para siempre. Una variable puede dejar de mostrarse (pública → privada), pero
 * nunca al revés: lo que se marcó como secreto no se destapa ni por `visibility` ni de
 * refilón con un `set --public`. Si hace falta un valor público, es OTRA variable (o se
 * borra esta y se crea de nuevo, y eso queda a la vista).
 */
export class PrivateStaysPrivate extends Error {
  constructor (key) {
    super(`${key} is private and a private variable cannot be made public: delete it and create it again as public`)
    this.code = 'PRIVATE_STAYS_PRIVATE'
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
 * @param {{ sealer?: object, recipients?: (owner: string) => any, signer?: (body: any) => any,
 *          defaultKey?: () => Uint8Array }} [opts]
 *   `sealer`: el puerto de sobres (`src/sealer.js`). Sin él, el store solo sabe leer y
 *   servir lo que ya hay — que es exactamente lo que hace falta para arrancar sin nada.
 *   `recipients(owner)`: a quién hay que envolverle la llave de ese cajón — los servicios
 *   de ese namespace y los aparatos que administran. Sale del acta, y por eso lo pone
 *   quien llama: este módulo no conoce el acta.
 *   `signer(body)`: firma del sobre, `{ seq, sig }` o `null`. Es lo que dice que el sobre
 *   salió de esta bóveda (§8.8).
 *   `defaultKey`: con qué sellar la privada de recuperación cuando el perfil NO tiene
 *   contraseña. Vive aquí, en un solo sitio, para que dé igual por qué puerta se entre.
 */
export function openSecretsStore (dir, { sealer = null, recipients = null, signer = null, defaultKey = null } = {}) {
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
  if (!data) data = { schemaVersion: SCHEMA_VERSION, ns: {}, dev: {}, recovery: null, history: [] }
  if (!data.dev) data.dev = {}
  if (!data.history) data.history = []
  // 0.47.0/0.48.0 guardaron una «política» DENTRO del cajón (salía como variable): fuera.
  for (const bag of Object.values(data.ns || {})) if (bag?.policy && typeof bag.policy === 'object' && !('v' in bag.policy)) delete bag.policy
  delete data.policies

  // v3 → v5 y v4 → v5 NO se hacen al abrir, y es deliberado: el daemon tiene que poder
  // arrancar y SERVIR sin nada (un perfil bloqueado sigue atendiendo a sus agentes). Un
  // archivo viejo se queda como está, sirviendo igual que siempre, hasta que alguien lo
  // convierta. Hasta entonces el despliegue se deshace con un reinicio.
  const isLegacy = () => data.schemaVersion === LEGACY_VERSION
  const needsMigration = () => data.schemaVersion === SEALED_MASTER_VERSION

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
  /** La llave con la que se abre la privada de recuperación: la dada, o la de la máquina. */
  const keyOr = (adminKey) => adminKey || defaultKey?.() || null

  /** Borra la rama si se quedó vacía: un scope (o un aparato) sin variables no existe. */
  const prune = (bag, k) => { if (bag[k] && Object.keys(bag[k]).length === 0) delete bag[k] }

  // --- forma de un cajón -------------------------------------------------------
  // v3: `bag[k]` ES el mapa de variables. v4/v5: `bag[k] = { vars, keyring }`.
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
  /** Solo las PÚBLICAS, con valor: lo único que puede salir de esta máquina en claro. */
  const publics = (bag, k) => Object.fromEntries(
    Object.entries(varsOf(bag, k)).filter(([, e]) => e.pub).map(([key, e]) => [key, e.v])
  )
  /**
   * Las entradas TAL CUAL van al bundle: la pública con su valor, la privada con su
   * sobre y su firma. No se descifra nada aquí — de eso vive todo esto.
   */
  const entriesOf = (bag, k) => ({ ...varsOf(bag, k) })

  /** La generación vigente de un cajón (la de `gen` mayor). */
  const topGen = (bag, k) => {
    const kr = bag[k]?.keyring || []
    return kr.reduce((best, g) => (!best || (g.gen || 0) > (best.gen || 0) ? g : best), null)
  }

  /**
   * UN CAMBIO A LA VEZ.
   *
   * Todo lo que toca el llavero es leer-modificar-escribir con un `await` en medio, así
   * que dos operaciones en vuelo se pisan la una a la otra. No es teórico: en v4 un
   * `rewrap` lanzado al aprobar un aparato volvía a sellar la copia maestra **con la
   * llave vieja** justo después de cambiar la contraseña del perfil, y el vault quedaba
   * abierto para cualquiera con una copia del disco, sin un solo mensaje de error.
   *
   * La cola es de este proceso, que es el único que escribe este archivo.
   */
  let cola = Promise.resolve()
  const enFila = (fn) => {
    const r = cola.then(fn, fn)
    cola = r.then(() => {}, () => {})
    return r
  }

  // --- histórico y recogida de generaciones ------------------------------------

  /** Guarda la versión que se va a pisar. Sin valores en claro: el sobre tal cual. */
  const pushHistory = (owner, key, before, by) => {
    if (!before || before.pub) return // una pública no es un secreto que revertir a ciegas
    data.history.push({ ts: Date.now(), owner, key, gen: before.gen, e: before.e, seal: before.seal || null, by: by || null })
    if (data.history.length > MAX_HISTORY) data.history = data.history.slice(-MAX_HISTORY)
  }

  /**
   * Tira las generaciones que ya no abre nada. Con una generación por escritura, el
   * llavero crecería sin fin; lo que hay que conservar es lo que todavía referencia una
   * variable viva o una entrada del histórico — ni una más, porque cada generación
   * conservada es una llave que sigue por ahí.
   */
  const gcKeyring = (bag, k, owner) => {
    if (!bag[k]) return
    const vivos = new Set()
    for (const e of Object.values(bag[k].vars || {})) if (!e.pub && e.gen != null) vivos.add(e.gen)
    for (const h of data.history) if (h.owner === owner && h.gen != null) vivos.add(h.gen)
    bag[k].keyring = (bag[k].keyring || []).filter((g) => vivos.has(g.gen))
  }

  /**
   * Abre la privada de RECUPERACIÓN. Es la única puerta de este módulo a un valor en
   * claro, y por eso es la única que pide la frase.
   */
  const openRecovery = async (adminKey) => {
    needSealer('read a private variable')
    if (!data.recovery?.priv) throw new NeedsPassword('this store has no recovery key yet')
    return sealer.openMaster(data.recovery.priv, keyOr(adminKey))
  }

  /**
   * El par de recuperación, creándolo si es la primera vez. Se sella con lo que haya:
   * con la frase si quien llama la trajo, y si no con la llave de la máquina — que es
   * la protección de siempre y no una nueva promesa. Cuando el perfil estrene
   * contraseña, `rekeyRecovery` lo vuelve a cerrar con ella.
   */
  const ensureRecovery = async (adminKey) => {
    if (data.recovery?.pub) return data.recovery
    needSealer('create the recovery key')
    const pair = await sealer.makeRecoveryPair()
    data.recovery = { pub: pair.pub, priv: await sealer.sealMaster(pair.priv, keyOr(adminKey)) }
    return data.recovery
  }

  /** Los destinatarios de un cajón: los que dice el acta, más la copia de recuperación. */
  const wrapAll = async (cek, owner) => {
    const members = (await recipients?.(owner)) || []
    const { wraps, sinLlave } = await sealer.wrapFor(cek, members)
    wraps[RECOVERY] = await sealer.wrapForKey(cek, data.recovery.pub)
    return { wraps, sinLlave }
  }

  return {
    /** `true` mientras el archivo siga en v3 (sin sellar). */
    isLegacy,
    /** `true` si sigue en v4 (sellado, pero con copia maestra): hay que convertirlo. */
    needsMigration,
    schemaVersion: () => data.schemaVersion,
    /** ¿La privada de recuperación está sellada solo con la llave de esta máquina? */
    recoveryPub: () => data.recovery?.pub || null,

    /**
     * MUCHAS ESCRITURAS, UN GUARDADO. Cargar la configuración de un servicio son veinte
     * variables pero un solo cambio: con un `save()` por variable, el archivo entero se
     * reescribía y se volvía a cifrar veinte veces.
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
     * Devuelve las entradas SIN abrir, más las envolturas **de este miembro y solo las
     * suyas**: el resto del llavero son las llaves de sus compañeros y no le hacen falta.
     * Van TODAS sus generaciones, no solo la última, porque desde v5 cada variable puede
     * venir de una escritura distinta. En v3 devuelve los valores en claro, como siempre.
     */
    /**
     * @param {string} ns
     * @param {string|null} devicePub
     * @param {{publicOnly?: boolean}} [opts] `publicOnly`: SOLO las públicas, y sin
     *   envolturas. Una pública está guardada en claro, así que no hay llave que repartir
     *   ni sobre que abrir — y por eso pedirlas no pasa por la aprobación (ver `handleSecrets`).
     */
    bundleFor (ns, devicePub = null, { publicOnly = false } = {}) {
      assertNs(ns)
      const todo = { ...entriesOf(data.ns, ns), ...(devicePub ? entriesOf(data.dev, devicePub) : {}) }
      // EL FILTRO LO HACE LA BÓVEDA, no quien pide. Si mandara todo y el cliente eligiera,
      // pedir «solo públicas» sería la forma de saltarse la aprobación y llevarse las
      // privadas igual — o sea justo lo contrario de lo que se quiere.
      const entries = publicOnly
        ? Object.fromEntries(Object.entries(todo).filter(([, e]) => e.pub))
        : todo
      if (isLegacy()) return { legacy: true, entries }
      // Sin privadas no hay nada que envolver: el paquete va sin llavero.
      if (publicOnly) return { entries, ns: null, dev: null, wraps: { ns: [], dev: [] } }
      const misWraps = (bag, k) => (bag[k]?.keyring || [])
        .filter((g) => g.wraps?.[devicePub])
        .map((g) => ({ gen: g.gen, wrap: g.wraps[devicePub] }))
      const ns1 = misWraps(data.ns, ns)
      const dev1 = devicePub ? misWraps(data.dev, devicePub) : []
      return {
        entries,
        // Compat con el bundle de v4, que llevaba UNA envoltura por cajón: se manda la
        // vigente ahí y la lista entera aparte. Quien sepa leer `wraps` usa la lista.
        ns: ns1[ns1.length - 1] || null,
        dev: dev1[dev1.length - 1] || null,
        wraps: { ns: ns1, dev: dev1 }
      }
    },

    /**
     * VER UN VALOR. Es lo único que pide la frase, y es lo que la frase significa desde
     * v5 (§8.3). Devuelve `null` si esa variable no existe.
     */
    async reveal (owner, key, adminKey = null) {
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      const e = varsOf(bag, k)[key]
      if (!e) return null
      if (e.pub) return e.v
      if (isLegacy()) return e.v
      const priv = await openRecovery(adminKey)
      const cek = await this._cekOf(bag, k, e.gen, priv)
      return sealer.openValue(cek, e.e)
    },


    /**
     * Las variables privadas de un cajón que ESE miembro **no puede abrir**: las que no
     * tienen envoltura para su llave en la generación vigente.
     *
     * Es la deuda del §8.7 vista desde el aparato en vez de desde el cajón. Un aparato
     * que entra después de escrita una variable no tiene envoltura de ella —y no la
     * puede tener, porque envolver exige abrir la CEK y eso pide la frase—, así que se
     * queda sin poder leerla. Eso es correcto y no se relaja; lo que no puede pasar es
     * que no se vea, que era el modo de fallo de verdad: un servicio en el acta,
     * aparentemente bien, que arranca sin configuración.
     *
     * @param {string} owner `ns:<scope>` o `dev:<pub>`
     * @param {string} memberPub la llave de FIRMA del miembro (así se indexan las envolturas)
     * @returns {string[]} nombres de variables, vacío si puede con todas
     */
    missingFor (owner, memberPub) {
      if (isLegacy()) return []
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      const out = []
      for (const [key, e] of Object.entries(varsOf(bag, k))) {
        if (e.pub) continue
        const g = (bag[k]?.keyring || []).find((x) => x.gen === e.gen)
        if (!g?.wraps?.[memberPub]) out.push(key)
      }
      return out
    },

    /**
     * Las generaciones de un cajón que a `memberPub` le faltan, con LA ENVOLTURA DE
     * QUIEN PREGUNTA para cada una. Es lo que necesita un aparato que administra para
     * completar a otro sin la frase: abre cada una con su llave y la vuelve a envolver
     * (`rewrapFor` de `@dotrino/identity`).
     *
     * Devuelve solo las generaciones que están EN USO (alguna variable las apunta): las
     * viejas no hacen falta y re-envolverlas sería repartir llaves que ya no abren nada.
     *
     * @returns {Array<{ gen: number, mine: any }>} vacío si quien pregunta tampoco puede
     */
    wrapsToShare (owner, memberPub, myPub) {
      if (isLegacy()) return []
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      const inUse = new Set(Object.values(varsOf(bag, k)).filter((e) => !e.pub).map((e) => e.gen))
      const out = []
      for (const g of bag[k]?.keyring || []) {
        if (!inUse.has(g.gen) || g.wraps?.[memberPub]) continue
        if (g.wraps?.[myPub]) out.push({ gen: g.gen, mine: g.wraps[myPub] })
      }
      return out
    },

    /**
     * Guarda una envoltura que hizo otro. La bóveda NO la puede comprobar —abrirla
     * exigiría la frase, que es justo lo que este camino evita—, así que lo que sí
     * comprueba es lo que puede: que la generación exista y que ese miembro no tuviera
     * ya una. Una envoltura mala deja al servicio sin leer, que se ve; no da acceso a
     * nadie.
     */
    putWrap (owner, gen, memberPub, wrap) {
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      const g = (bag[k]?.keyring || []).find((x) => x.gen === gen)
      if (!g) throw new Error(`putWrap: no existe la generación ${gen} de ${owner}`)
      if (!wrap?.epk || !wrap?.iv || !wrap?.ct) throw new Error('putWrap: envoltura mal formada')
      // SOLO AÑADE, NUNCA PISA. Quien re-envuelve es un servicio, y un servicio no
      // administra: si pudiera reemplazar una envoltura existente podría dejar sin leer
      // a otro miembro —o a quien administra— con una envoltura basura, y eso es
      // denegación de servicio disfrazada de reparto. Reemplazar es cosa de la bóveda,
      // por el camino de escribir (que estrena generación entera).
      if (g.wraps?.[memberPub]) throw new Error(`putWrap: ${memberPub.slice(0, 12)}… ya tiene envoltura de la generación ${gen}`)
      g.wraps = { ...(g.wraps || {}), [memberPub]: wrap }
      save()
      return true
    },


    /** @private La CEK de una generación, abierta con la privada de recuperación. */
    async _cekOf (bag, k, gen, priv) {
      const g = (bag[k]?.keyring || []).find((x) => x.gen === gen) || topGen(bag, k)
      const w = g?.wraps?.[RECOVERY]
      if (!w) throw new NeedsPassword(`there is no recovery copy of the key for generation ${gen}`)
      return sealer.openWrapWith(priv, w)
    },

    /**
     * Igual que `bundleFor` pero YA ABIERTO. Solo existe para las pruebas y para
     * diagnosticar: pide la frase. Nadie del camino de servir lo llama.
     */
    async openBundle (ns, devicePub = null, adminKey = null) {
      const b = this.bundleFor(ns, devicePub)
      if (b.legacy) return Object.fromEntries(Object.entries(b.entries).map(([k, e]) => [k, e.v]))
      const priv = await openRecovery(adminKey)
      const out = {}
      for (const [key, e] of Object.entries(b.entries)) {
        if (e.pub) { out[key] = e.v; continue }
        const [kind, k] = splitOwner(e.owner)
        const bag = kind === 'ns' ? data.ns : data.dev
        out[key] = await sealer.openValue(await this._cekOf(bag, k, e.gen, priv), e.e)
      }
      return out
    },

    // --- escritura: NO pide la frase (§8.1) --------------------------------------
    /**
     * Escribe en un cajón. `isPublic` es OPCIONAL a propósito: sin decir nada se
     * conserva lo que la variable ya era (rotar un valor no debe cambiar quién puede
     * verlo por olvido) y una variable nueva nace PRIVADA.
     *
     * `by` es quién la escribió (la pubkey del aparato), y va al histórico.
     */
    async set (ns, key, value, isPublic, { by = null } = {}) {
      assertNs(ns)
      return this._put(data.ns, ns, `ns:${ns}`, key, value, isPublic, by)
    },
    async setDevice (pub, key, value, isPublic, { by = null } = {}) {
      assertPub(pub)
      return this._put(data.dev, pub, `dev:${pub}`, key, value, isPublic, by)
    },
    /** @private */
    async _put (...a) { return enFila(() => this._putRaw(...a)) },
    /** @private El cuerpo, ya en fila (ver `enFila`). */
    async _putRaw (bag, k, owner, key, value, isPublic, by) {
      assertKeyValue(key, value)
      const vars = ensureBag(bag, k)
      const before = vars[key]
      const pub = isPublic === undefined ? !!before?.pub : !!isPublic
      if (before && !before.pub && pub) throw new PrivateStaysPrivate(key)

      // v3: se guarda como siempre. Convertir a sobres es un gesto aparte y explícito
      // (`migrate`), no algo que ocurra de refilón al escribir.
      if (isLegacy()) { vars[key] = { v: value, pub }; save(); return }
      if (needsMigration()) throw new NeedsMigration()

      // Una PÚBLICA se guarda en claro a propósito: eso es lo que significa marcarla.
      if (pub) { vars[key] = { v: value, pub: true }; save(); return }

      needSealer('write a private variable')
      await ensureRecovery(null)

      // CEK NUEVA, siempre: no se puede reutilizar la de antes sin poder abrirla.
      const cek = await sealer.newKey()
      const gen = (topGen(bag, k)?.gen || 0) + 1
      const { wraps, sinLlave } = await wrapAll(cek, owner)
      const e = await sealer.encrypt(cek, value, gen)
      // La FIRMA dice que este sobre salió de esta bóveda, y con qué acta (§8.8). Si no
      // hay con qué firmar, el sobre sale sin firma: guardar es más importante.
      const seal = signer ? await signer({ owner, key, gen, iv: e.iv, ct: e.ct }) : null

      pushHistory(owner, key, before, by)
      vars[key] = { pub: false, owner, gen, e, seal, at: Date.now(), by: by || null }
      bag[k].keyring = [...(bag[k].keyring || []), { gen, createdAt: Date.now(), wraps }]
      gcKeyring(bag, k, owner)
      save()
      return { gen, sinLlave }
    },

    async delete (ns, key) {
      assertNs(ns)
      return this._drop(data.ns, ns, `ns:${ns}`, key)
    },
    async deleteDevice (pub, key) {
      assertPub(pub)
      return this._drop(data.dev, pub, `dev:${pub}`, key)
    },
    /**
     * @private Borrar NO exige la frase: quitar algo no pide poder leerlo.
     *
     * Y borrar SE LLEVA SU HISTÓRICO. Si no, borrar una variable dejaría sus versiones
     * anteriores guardadas —cifradas, pero recuperables— y «borré esa credencial» sería
     * mentira. El histórico existe para revertir mientras la variable vive; cuando se va,
     * se va entera.
     */
    _drop (bag, k, owner, key) {
      const vars = varsOf(bag, k)
      const existed = key in vars
      if (!existed) return false
      delete vars[key]
      data.history = data.history.filter((h) => !(h.owner === owner && h.key === key))
      if (!isLegacy()) gcKeyring(bag, k, owner)
      if (Object.keys(vars).length === 0) prune(bag, k)
      save()
      return true
    },

    /**
     * Cambiar la visibilidad solo va en UNA dirección: de pública a privada (sellar el
     * valor, que es escribir y no pide nada). De privada a pública NO existe
     * (`PrivateStaysPrivate`): destapar un secreto no es una casilla, es borrarlo y
     * crear otro.
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
    async _setVis (...a) { return enFila(() => this._setVisRaw(...a)) },
    /** @private El cuerpo, ya en fila. */
    async _setVisRaw (bag, k, owner, key, isPublic, adminKey) {
      const vars = varsOf(bag, k)
      const e = vars[key]
      if (!e) return false
      const want = !!isPublic
      if (!!e.pub === want) return true
      if (!e.pub) throw new PrivateStaysPrivate(key)
      if (isLegacy()) { e.pub = false; save(); return true }
      if (needsMigration()) throw new NeedsMigration()

      // De pública a privada: es una escritura normal, con su generación y su firma.
      held++
      try { await this._putRaw(bag, k, owner, key, e.v, false, null) } finally { held-- }
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
    /**
     * QUIÉN puede abrir la generación vigente de un cajón (sus llaves de firma, más
     * `#recovery`). Es diagnóstico, no un secreto: saber a cuántos se les envolvió no
     * ayuda a abrir nada, y en cambio es lo único que responde de verdad a «¿quién
     * puede leer esto?» — que es la pregunta que uno se hace mirando un cajón.
     */
    recipientsIn (owner) {
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      return Object.keys(topGen(bag, k)?.wraps || {})
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

    // --- histórico: qué había antes, y cómo se vuelve ---------------------------
    /**
     * Las versiones anteriores, de la más nueva a la más vieja. SIN valores: son sobres.
     * Quien pueda abrirlos los abre con `revealHistory`; quien no, ve que existieron.
     */
    history (owner = null, key = null) {
      return data.history
        .filter((h) => (!owner || h.owner === owner) && (!key || h.key === key))
        .map((h) => ({ ts: h.ts, owner: h.owner, key: h.key, gen: h.gen, by: h.by || null, signed: !!h.seal }))
        .reverse()
    },

    /** El valor de una versión anterior. Pide la frase, como cualquier lectura. */
    async revealHistory (owner, key, ts, adminKey = null) {
      const h = data.history.find((x) => x.owner === owner && x.key === key && x.ts === ts)
      if (!h) return null
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      const priv = await openRecovery(adminKey)
      return sealer.openValue(await this._cekOf(bag, k, h.gen, priv), h.e)
    },

    /**
     * REVERTIR: coge una versión anterior y la vuelve a guardar. No es un modo especial
     * del store —es abrir y escribir—, así que hereda las dos reglas: abrir pide la
     * frase (o la hace quien puede leer, desde su aparato) y escribir no pide nada.
     */
    async revert (owner, key, ts, { adminKey = null, by = null } = {}) {
      const value = await this.revealHistory(owner, key, ts, adminKey)
      if (value == null) return false
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      await this._put(bag, k, owner, key, value, false, by)
      return true
    },

    // --- llavero: quién puede abrir cada cajón ----------------------------------
    /**
     * Re-envuelve la llave de lo YA GUARDADO a los miembros dados. Hace falta cuando
     * entra un aparato a un cajón que ya tiene variables: lo que se escriba desde ahora
     * ya se le envuelve solo, pero lo de antes está cerrado con llaves que él no tiene.
     *
     * Y por eso ESTO sí pide la frase: heredar lo viejo obliga a abrirlo.
     */
    async rewrap (...a) { return enFila(() => this._rewrap(...a)) },
    /** Los cajones que existen, para poder recorrerlos todos (`ns:…` y `dev:…`). */
    owners () {
      return [...Object.keys(data.ns).map((k) => `ns:${k}`), ...Object.keys(data.dev).map((k) => `dev:${k}`)]
    },
    /** @private */
    async _rewrap (owner, members, adminKey = null, { exact = false } = {}) {
      needSealer('re-wrap the key of a drawer')
      if (needsMigration()) throw new NeedsMigration()
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      if (!bag[k]) return { wrapped: 0, sinLlave: [] }
      const priv = await openRecovery(adminKey)
      let wrapped = 0
      const sinLlave = new Set()
      for (const g of bag[k].keyring || []) {
        const w = g.wraps?.[RECOVERY]
        if (!w) continue
        const cek = await sealer.openWrapWith(priv, w)
        const r = await sealer.wrapFor(cek, members)
        // `exact`: el llavero queda con lo que dice el acta y NADA más. Es lo que hace
        // falta para rehacerlo al abrir la bóveda:
        //   · una envoltura basura que metió alguien se reemplaza por la buena;
        //   · una que sobra —de quien administraba antes de que este cajón tuviera
        //     dueño, o de un miembro inventado— se cae.
        // Sin `exact` se fusiona, que es lo correcto cuando solo se está repartiendo a
        // unos pocos y no se quiere tocar al resto.
        //
        // OJO con lo que esto NO es: quitarle la envoltura a alguien no le quita lo que
        // ya leyó ni la llave que se haya guardado. Cortar de verdad es `rotate`.
        g.wraps = exact ? { ...r.wraps, [RECOVERY]: w } : { ...g.wraps, ...r.wraps }
        for (const s of r.sinLlave) sinLlave.add(s)
        wrapped += Object.keys(r.wraps).length
      }
      save()
      return { wrapped, sinLlave: [...sinLlave] }
    },

    /**
     * ROTA de verdad: vuelve a cifrar las variables privadas del cajón con llaves nuevas
     * y solo para los miembros dados. Es lo que corta el acceso de quien salió —
     * quitarle la envoltura no basta, porque si guardó la llave sigue abriendo lo que ya
     * estaba cifrado con ella.
     *
     * No devuelve lo que el expulsado ya leyó. Eso no se puede deshacer y no se promete.
     */
    async rotate (...a) { return enFila(() => this._rotate(...a)) },
    /** @private */
    async _rotate (owner, members, adminKey = null) {
      needSealer('rotate the key of a drawer')
      if (needsMigration()) throw new NeedsMigration()
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      if (!bag[k]) return { rotated: 0, sinLlave: [] }
      const priv = await openRecovery(adminKey)

      const vars = bag[k].vars || {}
      const claras = {}
      for (const [key, e] of Object.entries(vars)) {
        if (!e.pub) claras[key] = await sealer.openValue(await this._cekOf(bag, k, e.gen, priv), e.e)
      }
      // Se tira el llavero entero: las generaciones viejas son justamente lo que el que
      // se fue podría abrir. Con ellas se va el histórico de este cajón, que estaba
      // cifrado con ellas — rotar es renunciar a poder revertir lo de antes.
      bag[k].keyring = []
      data.history = data.history.filter((h) => h.owner !== owner)
      const sinLlave = new Set()
      let gen = 0
      for (const [key, value] of Object.entries(claras)) {
        const cek = await sealer.newKey()
        gen += 1
        const { wraps, sinLlave: faltan } = await sealer.wrapFor(cek, members)
        wraps[RECOVERY] = await sealer.wrapForKey(cek, data.recovery.pub)
        for (const s of faltan) sinLlave.add(s)
        const e = await sealer.encrypt(cek, value, gen)
        const seal = signer ? await signer({ owner, key, gen, iv: e.iv, ct: e.ct }) : null
        vars[key] = { pub: false, owner, gen, e, seal, at: Date.now(), by: null }
        bag[k].keyring.push({ gen, createdAt: Date.now(), wraps })
      }
      save()
      return { rotated: Object.keys(claras).length, sinLlave: [...sinLlave], gen, cambio: true }
    },

    /**
     * Se va un aparato, se van sus variables. Lo llama el vault al quitar un
     * miembro: dejarlas sería guardar la configuración de una llave que ya no
     * entra, y reaparecería sola si mañana se enrola otro aparato con esa llave.
     *
     * NO exige la frase: es la mitad del interruptor de emergencia. Su cajón `dev`
     * estaba sellado solo a él, así que borrarlo es inmediato y completo. Lo que sí queda
     * pendiente es rotar los `ns` que compartía (ver `rotate`).
     */
    forgetDevice (pub) {
      assertPub(pub)
      const keys = Object.keys(varsOf(data.dev, pub))
      if (keys.length || data.dev[pub]) { delete data.dev[pub]; save() }
      data.history = data.history.filter((h) => h.owner !== `dev:${pub}`)
      return keys.length
    },

    /**
     * Quita a un miembro del llavero de un cajón, sin abrir nada. Es lo que se puede
     * hacer SIN la frase cuando alguien sale: deja de poder abrir lo que se guarde en
     * adelante y lo que aún no había abierto. Lo que ya guardó no se arregla así — para
     * eso está `rotate`, que sí pide la frase.
     */
    unwrap (owner, pub) {
      if (isLegacy() || needsMigration()) return 0
      const [kind, k] = splitOwner(owner)
      const bag = kind === 'ns' ? data.ns : data.dev
      if (!bag[k]) return 0
      let n = 0
      for (const g of bag[k].keyring || []) {
        if (g.wraps?.[pub]) { delete g.wraps[pub]; n++ }
      }
      if (n) save()
      return n
    },

    /**
     * Vuelve a cerrar la privada de RECUPERACIÓN con otra llave. Es lo que hay que hacer
     * al poner, cambiar o quitar la contraseña del perfil: los sobres de las variables no
     * se tocan —siguen sellados a cada destinatario—, lo único que cambia es con qué se
     * abre la copia del dueño.
     *
     * Sin esto, cambiar la contraseña dejaría los secretos ILEGIBLES para él: la copia
     * seguiría sellada con la llave vieja y ya nadie tendría cómo abrirla. Es barato (un
     * solo sobre) y es obligatorio.
     *
     * `null` en cualquiera de las dos significa «la del perfil sin contraseña».
     */
    async rekeyRecovery (...a) { return enFila(() => this._rekeyRecovery(...a)) },
    /**
     * ¿ESTA llave abre la copia de recuperación? Lanza si no.
     *
     * Sirve para saber con cuál está cerrada sin tocar nada — que es lo que hace falta para
     * decidir si hay que migrarla. Preguntarlo intentando reenvolver un cajón mezcla dos
     * cosas y deja el fallo diciendo «wrong password» sobre el cajón, que no es donde está.
     */
    async recoveryOpensWith (key) {
      needSealer('check the recovery key')
      if (!data.recovery?.priv) throw new NeedsPassword('this store has no recovery key yet')
      await sealer.openMaster(data.recovery.priv, keyOr(key))
      return true
    },
    /** @private */
    async _rekeyRecovery (oldKey, newKey) {
      if (isLegacy()) return { rekeyed: false, reason: 'v3' }
      if (!data.recovery?.priv) return { rekeyed: false, reason: 'no-recovery' }
      needSealer('change the profile password')
      const priv = await sealer.openMaster(data.recovery.priv, keyOr(oldKey))
      data.recovery.priv = await sealer.sealMaster(priv, keyOr(newKey))
      save()
      return { rekeyed: true }
    },

    // --- conversión a v5 ---------------------------------------------------------
    /**
     * Lleva el archivo a v5, venga de donde venga:
     *
     *   · **desde v3** (valores en claro): no hace falta la frase para nada. Se sella
     *     cada valor a sus destinatarios y se estrena el par de recuperación.
     *   · **desde v4** (sellado con copia maestra): la frase hace falta UNA vez, para
     *     abrir esa copia. A partir de ahí, escribir no la pide nunca más.
     *
     * Verificar antes de reemplazar, igual que `migrateFile()` de `atrest.js`: se
     * construye la forma nueva, se vuelve a abrir **valor por valor** y se compara con
     * el original, y solo entonces se escribe. Si algo no cuadra no se toca nada y se
     * lanza: media migración es peor que ninguna.
     */
    async migrate (...a) { return enFila(() => this._migrate(...a)) },
    /** @private */
    async _migrate (membersOf, adminKey = null) {
      if (data.schemaVersion === SCHEMA_VERSION) return { migrated: false, reason: 'already-v5' }
      needSealer('seal the store')
      const desde = data.schemaVersion

      // De v4: las CEK viejas viven en la copia maestra, y para abrirla hace falta la
      // frase. Es la única vez que se pide.
      const master = desde === SEALED_MASTER_VERSION ? await sealer.openMaster(data.master, keyOr(adminKey)) : null
      const claro = async (owner, e) => {
        if (e.pub) return e.v
        if (desde === LEGACY_VERSION) return e.v
        return sealer.decrypt(master, e.e, e.owner || owner)
      }

      const pair = await sealer.makeRecoveryPair()
      const next = {
        schemaVersion: SCHEMA_VERSION,
        ns: {},
        dev: {},
        recovery: { pub: pair.pub, priv: await sealer.sealMaster(pair.priv, keyOr(adminKey)) },
        // El histórico empieza aquí: de lo de antes no se guardó ninguna versión previa.
        history: []
      }
      const antes = {}
      const sinLlave = {}

      for (const [kind, src, dst] of [['ns', data.ns, next.ns], ['dev', data.dev, next.dev]]) {
        for (const [k, bag] of Object.entries(src)) {
          const owner = `${kind}:${k}`
          const entradas = desde === LEGACY_VERSION ? (bag || {}) : (bag?.vars || {})
          const vars = {}
          const keyring = []
          // UNA SOLA generación para todo el cajón, y no es una excepción a «una por
          // escritura»: convertir es UN acto, y aquí la bóveda tiene delante todos los
          // valores en claro, así que puede sellarlos con la misma llave sin tener que
          // recuperar nada. Además deja el cajón como lo espera un agente que todavía no
          // se ha actualizado —una envoltura por cajón—, y eso es lo que permite convertir
          // sin apagar a nadie. Lo que se escriba DESPUÉS ya estrena generación.
          const gen = 1
          let cek = null
          for (const [key, e] of Object.entries(entradas)) {
            const value = await claro(owner, e)
            antes[`${owner}\u0000${key}`] = value
            if (e.pub) { vars[key] = { v: value, pub: true }; continue }
            if (!cek) {
              cek = await sealer.newKey()
              const { wraps, sinLlave: faltan } = await sealer.wrapFor(cek, (await membersOf(owner)) || [])
              wraps[RECOVERY] = await sealer.wrapForKey(cek, next.recovery.pub)
              if (faltan.length) sinLlave[owner] = faltan
              keyring.push({ gen, createdAt: Date.now(), wraps })
            }
            const sobre = await sealer.encrypt(cek, value, gen)
            const seal = signer ? await signer({ owner, key, gen, iv: sobre.iv, ct: sobre.ct }) : null
            vars[key] = { pub: false, owner, gen, e: sobre, seal, at: Date.now(), by: null }
          }
          dst[k] = { vars, keyring }
        }
      }

      // Releer lo escrito y comparar contra el original, antes de reemplazar nada.
      const priv = await sealer.openMaster(next.recovery.priv, keyOr(adminKey))
      for (const [kind, dst] of [['ns', next.ns], ['dev', next.dev]]) {
        for (const [k, bag] of Object.entries(dst)) {
          const owner = `${kind}:${k}`
          for (const [key, e] of Object.entries(bag.vars)) {
            let abierto
            if (e.pub) abierto = e.v
            else {
              const g = bag.keyring.find((x) => x.gen === e.gen)
              abierto = await sealer.openValue(await sealer.openWrapWith(priv, g.wraps[RECOVERY]), e.e)
            }
            if (abierto !== antes[`${owner}\u0000${key}`]) {
              throw new Error(`secrets: the migration check failed on ${owner}/${key}; nothing was touched`)
            }
          }
        }
      }

      // Copia de lo anterior antes de pisarlo. Con nodos en producción, deshacer tiene
      // que ser un `mv`, no una restauración. La borra el operador a mano.
      writeJson(`${file}.v${desde}.bak`, data, atRest)
      data = next
      flush()
      return { migrated: true, from: desde, sinLlave }
    }
  }
}

/** `ns:proxy` → `['ns','proxy']`. El `dev:` lleva dentro un JWK con dos puntos. */
function splitOwner (owner) {
  const i = String(owner).indexOf(':')
  if (i < 0) throw new Error('invalid drawer: expected "ns:<name>" or "dev:<pubkey>"')
  return [owner.slice(0, i), owner.slice(i + 1)]
}
