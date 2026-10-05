/**
 * profiles.js — registro MULTI-PERFIL del vault.
 *
 * Un mismo PC puede custodiar varias identidades del usuario (personal, trabajo…).
 * Cada perfil es una maestra distinta y vive en su PROPIO subdirectorio, así que
 * todo lo que ya era «por dir» (identity.json, peers, vault.json, threads.json,
 * secrets.json, activity.log) queda naturalmente aislado entre perfiles: un
 * dispositivo enrolado en un perfil no ve ni firma nada del otro.
 *
 *   <root>/profiles.json      este registro: [{ id, name, createdAt, pwd? }] + activo
 *   <root>/transport.json     keypair del proxy-client (a nivel PROCESO, no por perfil)
 *   <root>/p/<id>/…           los datos de cada perfil (incluida su maestra)
 *
 * CONTRASEÑA (opcional, por perfil): es un VERIFICADOR scrypt (v2; v1 era PBKDF2 y se
 * asciende al desbloquear) que NO cifra nada en reposo.
 * Y solo bloquea EDITAR el perfil: el daemon sigue firmando y sirviendo a los
 * dispositivos ya enrolados aunque el perfil esté bloqueado, para que un reinicio
 * del PC no deje las apps muertas hasta que alguien teclee la contraseña.
 * Protege contra que otro que se siente en la máquina —o un dispositivo enrolado—
 * te reescriba el perfil; NO contra quien pueda leer el disco (para eso hace falta
 * cifrado en reposo, ver `paths.js`).
 */
import fs from 'node:fs'
import crypto2 from 'node:crypto'
import path from 'node:path'
import { dataDir, ensureDir, readJson, writeJson } from './paths.js'
import { atRestFor, migrateFile, kekFor, encryptText, decryptText } from './atrest.js'
import { probe as probeKek, writeConfig as writeKekConfig, configFromEnv } from './atrest.js'
import { keyDirName, keyOwnerOf } from './keyowner.js'

const REGISTRY = 'profiles.json'
const PWD_ITER = 300000 // PBKDF2 del verificador v1 (heredado); v2 usa scrypt

/**
 * EL MOLINO, en un solo sitio. Estaba escrito a mano en cada llamada, y con la contraseña
 * del admin eso deja de ser cosmética: **el navegador tiene que derivar con exactamente
 * estos números**. Si aquí se cambia uno y allá no, la contraseña «deja de funcionar» sin
 * que nada diga por qué, que es la clase de fallo que este proyecto viene evitando.
 *
 * Por eso también se le mandan al admin (`secondaryParams`) en vez de que los copie.
 */
export const SCRYPT = Object.freeze({ N: 16384, r: 8, p: 1, len: 32 })
const MAX_NAME = 40
/**
 * Lo MÍNIMO que se acepta al poner una contraseña.
 *
 * Eran 4 caracteres, y eso se quedó corto el día que los secretos pasaron a sellarse:
 * desde entonces la contraseña no bloquea una consola, **es la llave** que abre la
 * copia maestra, y todo el cifrado vale lo que valga ella. Cuatro dígitos son 10.000
 * combinaciones — se prueban enteras en un rato aunque la derivación sea cara.
 *
 * No se piden mayúsculas ni símbolos a propósito: hacen la frase difícil de recordar
 * y fácil de adivinar. Lo que da fuerza es la LONGITUD y que no la elija un humano;
 * por eso lo que se pide en pantalla son varias palabras al azar.
 */
const PWD_MIN = 12

/**
 * Cuánto tarda el freno en OLVIDAR los fallos. Sin esto la cuenta solo subía —solo la
 * borraba un acierto—, así que teclear mal la contraseña cinco veces un martes te dejaba
 * el vault con esperas de minutos el miércoles, y cada intento nuevo (aunque fuera el
 * bueno) la alargaba sin llegar a comprobarse: la bóveda quedaba cerrada para su dueño.
 * El freno tiene que estorbar a una RÁFAGA, no a quien vuelve al día siguiente.
 */
const TRIES_FORGET_MS = 15 * 60 * 1000

/**
 * BLOQUEO AUTOMÁTICO. Cuánto aguanta abierto el candado sin que nadie lo use.
 *
 * Abrir la bóveda dejaba la consola abierta hasta que alguien la cerraba a mano o
 * reiniciaba el servicio — y el servicio de un PC de escritorio no se reinicia en semanas.
 * O sea que teclear la contraseña una vez un lunes dejaba la máquina administrable para
 * quien pasara por delante el jueves. Un candado que solo se cierra reiniciando no es un
 * candado.
 *
 * El plazo se cuenta desde el ÚLTIMO USO (`touch`), no desde que se abrió: quien está
 * trabajando no se queda fuera a media faena, y quien se levanta de la silla lo encuentra
 * cerrado. Y vence solo, sin temporizador: se mira la hora al preguntar (`isOpen`), así
 * que no hay nada que limpiar ni un `setTimeout` que mantenga vivo al proceso.
 *
 * Como todo el candado, esto es de la CONSOLA: al vencer, los aparatos ya emparejados
 * siguen firmando, leyendo y guardando. Lo que se cierra es administrar y mirar.
 */
const AUTO_LOCK_MS = 5 * 60 * 1000

/**
 * Archivos de un perfil que en la versión mono-perfil vivían sueltos en la raíz.
 *
 * `atrest.salt` va en la lista y NO es un detalle: los datos van cifrados con una clave
 * derivada del salt que vive JUNTO a ellos, así que mover los archivos sin el salt los
 * dejaría ilegibles (la clave se derivaría de un salt nuevo). Se mudan juntos.
 */
const LEGACY_FILES = ['identity.json', 'peers.json', 'vault.json', 'threads.json', 'secrets.json', 'activity.log', 'atrest.salt']

const b64 = (buf) => Buffer.from(new Uint8Array(buf)).toString('base64')

/**
 * El verificador del candado.
 *
 * v2 es **scrypt, con el mismo coste que `adminKey`**, y no por gusto: este valor vive
 * EN CLARO en `profiles.json`, así que quien tenga el disco lo ataca fuera de línea. Si
 * es más barato que la llave de verdad, se convierte en el camino corto para llegar a
 * ella — que es exactamente lo que pasaba con PBKDF2 al lado de un scrypt.
 *
 * v1 (PBKDF2) se sigue aceptando porque hay perfiles con él en el disco, y se ASCIENDE
 * a v2 en el primer desbloqueo correcto: es el único momento en que se tiene la
 * contraseña en la mano.
 */
function deriveScryptPwd (password, saltB64) {
  const salt = Buffer.from(saltB64, 'base64')
  return b64(crypto2.scryptSync(String(password || ''), salt, SCRYPT.len, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p }))
}

/** PBKDF2-SHA256 → verificador base64 (v1, heredado). */
async function derivePwd (password, saltB64, iter) {
  const salt = Buffer.from(saltB64, 'base64')
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(password)), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, km, 256)
  return b64(bits)
}

/**
 * LAS PUERTAS: de qué se saca la llave que abre cada una.
 *
 *   · `password`  scrypt(contraseña, salt) — el mismo molino que antes daba `K` directamente.
 *   · `fido2`     HKDF(hmac-secret de la llave), con toque.
 *   · `chalresp`  HKDF(respuesta HMAC-SHA1 de la ranura 2), sin toque.
 *   · las dos de hardware con `withPassword`: HKDF(scrypt(contraseña) ‖ secreto de la llave).
 *     Hacen falta las DOS cosas.
 *   · `machine`   la llave de esta máquina — la de un perfil sin candado.
 *
 * El `info` de HKDF lleva el tipo: los bytes de una llave no pueden abrir la puerta de otro tipo.
 */
const HW_INFO = { fido2: 'dotrino-vault/door/fido2/v1', chalresp: 'dotrino-vault/door/chalresp/v1' }
const HW_KINDS = Object.keys(HW_INFO)

const scryptKey = (password, saltB64) => crypto2.scryptSync(String(password), Buffer.from(saltB64, 'base64'), SCRYPT.len, { N: SCRYPT.N, r: SCRYPT.r, p: SCRYPT.p })

/** La llave de una puerta con lo que se trae, o `null` si falta algo para esa puerta. */
function doorKey (door, { password = null, secret = null } = {}) {
  if (door.kind === 'password') return password ? scryptKey(password, door.salt) : null
  if (!HW_INFO[door.kind] || !secret?.length) return null
  if (door.withPassword && !password) return null
  const ikm = door.withPassword ? Buffer.concat([scryptKey(password, door.salt), Buffer.from(secret)]) : Buffer.from(secret)
  const k = Buffer.from(crypto2.hkdfSync('sha256', ikm, Buffer.alloc(0), HW_INFO[door.kind] + (door.withPassword ? '+password' : ''), 32))
  ikm.fill(0)
  return k
}

const newDoorId = () => crypto2.randomBytes(4).toString('hex')
const realDoors = (p) => (p.doors || []).filter((d) => d.kind !== 'machine')
/** Tiene candado: alguna puerta de verdad, o la contraseña de antes de las puertas. */
const isProtected = (p) => !!p.pwd || realDoors(p).length > 0
/** Ya tiene llave de perfil (con o sin candado). */
const hasKey = (p) => !!p.pwd || (p.doors || []).length > 0

function checkPassword (password) {
  if (!password || String(password).length < PWD_MIN) {
    throw Object.assign(new Error(`password must be at least ${PWD_MIN} characters: use several random words`),
      { code: 'PASSWORD_TOO_SHORT', min: PWD_MIN })
  }
}

/** Fabrica una puerta: el sobre de `K` y lo que hace falta para volver a pedírselo a la llave. */
function makeDoor (K, spec = {}, { checkMin = true } = {}) {
  const kind = spec.kind
  if (kind !== 'password' && !HW_INFO[kind]) throw Object.assign(new Error('unknown door kind: ' + kind), { code: 'BAD_DOOR' })
  const withPassword = kind !== 'password' && !!spec.password
  if ((kind === 'password' || withPassword) && checkMin) checkPassword(spec.password)
  if ((kind === 'password' || withPassword) && !spec.password) throw Object.assign(new Error('a password is required'), { code: 'BAD_DOOR' })
  const door = { id: newDoorId(), kind, createdAt: Date.now(), ...(spec.label ? { label: String(spec.label).slice(0, MAX_NAME) } : {}) }
  if (kind === 'password' || withPassword) door.salt = b64(crypto2.randomBytes(32))
  if (withPassword) door.withPassword = true
  if (kind === 'fido2') {
    if (!spec.credId || !spec.hsalt) throw Object.assign(new Error('a fido2 door needs credId and hsalt'), { code: 'BAD_DOOR' })
    Object.assign(door, { credId: spec.credId, hsalt: spec.hsalt })
  }
  if (kind === 'chalresp') {
    if (!/^[0-9a-f]{2,126}$/.test(spec.challenge || '')) throw Object.assign(new Error('a chalresp door needs a hex challenge'), { code: 'BAD_DOOR' })
    Object.assign(door, { challenge: spec.challenge, ...(spec.serial ? { serial: String(spec.serial) } : {}) })
  }
  const secret = spec.secret ? Buffer.from(spec.secret) : null
  if (HW_INFO[kind] && !secret?.length) throw Object.assign(new Error('the key gave nothing to seal the door with'), { code: 'BAD_DOOR' })
  const k = doorKey(door, { password: spec.password, secret })
  door.wrapped = encryptText(b64(K), k)
  // Se comprueba ANTES de guardar: una puerta que no abre es peor que no tenerla.
  const back = Buffer.from(decryptText(door.wrapped, k), 'base64')
  k.fill(0)
  if (!back.equals(Buffer.from(K))) throw Object.assign(new Error('the new door does not open: not saved'), { code: 'BAD_DOOR' })
  return door
}

/** Lo que se enseña de una puerta: nada secreto. `credId`/`hsalt`/`challenge` no abren nada sin la llave. */
const publicDoor = (d) => ({
  id: d.id, kind: d.kind, createdAt: d.createdAt || null,
  ...(d.label ? { label: d.label } : {}), ...(d.withPassword ? { withPassword: true } : {}),
  ...(d.kind === 'fido2' ? { credId: d.credId, hsalt: d.hsalt } : {}),
  ...(d.kind === 'chalresp' ? { challenge: d.challenge, ...(d.serial ? { serial: d.serial } : {}) } : {})
})
const publicDoors = (p) => [
  ...(p.pwd ? [{ id: 'password', kind: 'password', legacy: true }] : []),
  ...realDoors(p).map(publicDoor)
]

/** Las credenciales en su forma: la contraseña sola (texto) se acepta por compatibilidad. */
function normCreds (c) {
  if (typeof c === 'string' || c == null) return { password: c || null, door: null, secret: null }
  return {
    password: c.password || null,
    door: c.door || null,
    secret: c.secret ? (typeof c.secret === 'string' ? Buffer.from(c.secret, 'base64') : Buffer.from(c.secret)) : null
  }
}

/**
 * El nombre de la carpeta DE PASO, la que existe solo mientras se acuña la llave.
 *
 * La llave se genera antes de escribirse (`crypto.subtle.generateKey` y luego el kv), pero
 * la única API que tenemos —`Identity.connect({ dir })`— recibe la carpeta por delante y
 * hace las dos cosas de un tirón: no hay costura donde meterse a preguntar la huella. Así
 * que se acuña aquí y en cuanto se sabe de quién es, la carpeta se MUEVE a su nombre.
 * El punto delante la deja fuera de la lista de perfiles si algo se corta a medias.
 */
const stagingName = () => '.new-' + crypto.randomUUID().slice(0, 8)
const cleanName = (name) => String(name || '').slice(0, MAX_NAME)

/**
 * @param {string} root  dir de datos
 * @param {{ autoLockMs?: number, onAutoLock?: (id: string) => void }} [opts]
 *   `autoLockMs`: 0 desactiva el bloqueo automático (las pruebas lo acortan).
 *   `onAutoLock`: se avisa cuando un perfil se cierra solo, para poder decirlo en el log.
 */
export function openProfiles (root = dataDir(), { autoLockMs = AUTO_LOCK_MS, onAutoLock = null } = {}) {
  const file = path.join(root, REGISTRY)
  // CIFRADO EN REPOSO, como todo lo demás. Era el único archivo del vault sin códec, y
  // lleva dentro el verificador del candado. No protege de quien tenga el disco entero
  // —el material de la llave vive en ese mismo disco, y eso está dicho en voz alta en
  // `docs/secretos-sellados.md`— pero sí de que el registro viaje en claro en un
  // respaldo o en una carpeta compartida por descuido, que es lo que el códec cubre
  // para el resto. La migración verifica antes de reemplazar y es de una sola vez.
  ensureDir(root)
  // LA RAÍZ TAMBIÉN NECESITA EL PROVEEDOR DEL ENTORNO, y esto lo destapó un contenedor:
  // los perfiles nacían con la clave en el KMS, pero el REGISTRO de perfiles seguía con
  // la de la máquina — así que al recrear el contenedor la bóveda no arrancaba igual,
  // solo que fallando un paso antes. No guarda el contenido de ningún perfil (la lista y
  // el verificador del candado), pero sin él no hay bóveda.
  //
  // Solo si está por estrenar: si el registro ya existe cifrado con la clave de antes,
  // cambiarle el proveedor lo dejaría ilegible. Ahí se migra con `atrest rekey`.
  if (!fs.existsSync(path.join(root, 'atrest.json'))) {
    const kek = configFromEnv()
    if (kek && !fs.existsSync(file)) {
      probeKek(root, kek)
      writeKekConfig(root, kek)
    }
  }
  try { migrateFile(file, kekFor(root)) } catch (_) {}
  const atRest = atRestFor(root)
  let data = readJson(file, null, atRest)
  if (!data || !Array.isArray(data.profiles)) data = { v: 1, current: null, profiles: [] }
  const save = () => writeJson(file, data, atRest)

  // Perfiles DESBLOQUEADOS en esta ejecución del daemon (en memoria: un reinicio
  // vuelve a bloquear, igual que cerrar la pestaña en el navegador), cada uno con la
  // hora a la que se cierra solo si nadie lo usa (ver AUTO_LOCK_MS).
  const unlocked = new Map() // id -> vence (ms epoch)

  /**
   * LA LLAVE DERIVADA DE LA FRASE, mientras el perfil está abierto.
   *
   * Hasta ahora «abierto» era SOLO una bandera: la llave se derivaba en el `unlock`, se
   * usaba para rehacer el llavero y se borraba en el `finally` de la misma línea. La
   * consecuencia se veía media hora después y no se parecía a su causa — enrolar un
   * servicio con la bóveda recién abierta contestaba «wrong password», porque envolverle
   * la llave de su cajón exige abrir la copia de recuperación y para eso hace falta la
   * frase, que ya no estaba. El aparato entraba y descubría al PRIMER ARRANQUE que no
   * podía leer su cajón (dueño, 2026-08-31: «el rato de enrolar la bóveda está abierta,
   * así que debía crear los sobres sin preguntar»).
   *
   * Lo que se guarda NO es la contraseña: es la llave que sale de ella por scrypt, y solo
   * mientras el candado esté abierto. Se borra —con `wipe`, no con un `delete`— al
   * cerrarse, al cerrarse solo por inactividad, al borrar el perfil y al reiniciar el
   * daemon. Ese es el precio, y es el mismo que ya se paga por poder sellar actas
   * estando abierta: lo que acota la exposición es el auto-candado, no el olvido.
   */
  const llaves = new Map() // id -> Uint8Array (la llave derivada, solo si está abierto)
  // La `K` de los perfiles SIN candado que la guardan bajo la llave de la máquina (`openKey`).
  const porMaquina = new Map()

  /** Borra el material de verdad antes de soltar la referencia. */
  const olvidar = (id) => {
    const k = llaves.get(id)
    if (k) { try { k.fill(0) } catch (_) {} }
    llaves.delete(id)
    const m = porMaquina.get(id)
    if (m) { try { m.fill(0) } catch (_) {} }
    porMaquina.delete(id)
  }

  /** ¿Sigue abierto? Vence al MIRARLO, así que no hace falta ningún temporizador. */
  const isOpen = (id) => {
    const until = unlocked.get(id)
    if (until == null) return false
    if (autoLockMs > 0 && Date.now() >= until) {
      unlocked.delete(id)
      olvidar(id)
      // El aviso va después de borrarlo: quien lo escuche verá el perfil ya cerrado.
      try { onAutoLock?.(id) } catch (_) {}
      return false
    }
    return true
  }
  /** Abre (o estira) el plazo. Todo lo que abre el candado pasa por aquí. */
  const open = (id) => { unlocked.set(id, Date.now() + (autoLockMs > 0 ? autoLockMs : Number.MAX_SAFE_INTEGER)) }

  const find = (id) => data.profiles.find((p) => p.id === id) || null
  const dirOf = (id) => path.join(root, 'p', id)

  const entry = (p) => ({
    id: p.id,
    name: p.name || '',
    createdAt: p.createdAt || null,
    protected: isProtected(p),
    locked: isProtected(p) && !isOpen(p.id),
    // Con qué se abre: contraseña, YubiKey… Es DATO, y la CLI lo necesita para saber qué pedir.
    doors: publicDoors(p),
    // Hasta cuándo sigue abierto si nadie lo toca. Es DATO: la consola lo enseña para
    // que el cierre no llegue por sorpresa.
    ...(isProtected(p) && isOpen(p.id) && autoLockMs > 0 ? { until: unlocked.get(p.id) } : {}),
    current: p.id === data.current,
    // Nació para adoptar la cuenta de un aparato (camino A) y todavía no lo ha hecho.
    ...(p.adopt ? { adopt: true } : {})
  })

  function assertExists (id) {
    const p = find(id)
    if (!p) throw new Error('profile does not exist: ' + id)
    return p
  }

  /**
   * EL FRENO DE FUERZA BRUTA, en un solo sitio porque ahora hay DOS puertas.
   *
   * Tras 5 fallos, espera exponencial (2^n s, tope 5 min) persistida en el registro. Los
   * fallos VIEJOS se olvidan (`TRIES_FORGET_MS`): sigue frenando una ráfaga, pero no
   * convierte un despiste de ayer en un vault que ya no se abre.
   *
   * **Las dos contraseñas cuentan en el MISMO contador**, y no es un detalle: si cada una
   * llevara el suyo, probar por un camino no frenaría el otro y el freno valdría la mitad.
   *
   * Lanza con CÓDIGO: la TUI es bilingüe y lo traduce, y la CLI lo dice con sus palabras.
   * Sin código, el rechazo llegaba como un texto suelto del daemon, indistinguible de
   * «se volvió a pedir la contraseña porque sí».
   */
  function frenar (p) {
    let tries = p.tries || { n: 0, at: 0 }
    if (tries.at && Date.now() - tries.at > TRIES_FORGET_MS) {
      tries = { n: 0, at: 0 }
      if (p.tries) { delete p.tries; save() }
    }
    const waitMs = tries.n >= 5 ? Math.min(2 ** (tries.n - 4) * 1000, 5 * 60 * 1000) : 0
    const left = tries.at + waitMs - Date.now()
    if (left > 0) {
      throw Object.assign(new Error(`too many tries: wait ${Math.ceil(left / 1000)} s`),
        { code: 'TOO_MANY_TRIES', waitSec: Math.ceil(left / 1000) })
    }
    return tries
  }

  /**
   * La `K` de un perfil con candado, a partir de lo que se trae. Prueba solo las puertas que
   * encajan con eso. Cuando nada encaja (una contraseña para un perfil que solo abre con llave)
   * se dice con su código y NO cuenta como intento: no es adivinar, es equivocarse de puerta.
   *
   * La contraseña de ANTES de las puertas (`p.pwd` + `p.kdf`, `K = scrypt(contraseña)`) se sigue
   * aceptando, y al acertarla se pasa a puerta: es el único momento en que se tiene en la mano.
   */
  async function resolveK (p, { password, door, secret }) {
    const real = realDoors(p)
    let cands
    if (door) {
      const d = real.find((x) => x.id === door)
      if (!d) throw Object.assign(new Error('that key is not a door of this profile'), { code: 'NO_SUCH_DOOR' })
      if (d.withPassword && !password) throw Object.assign(new Error('this key also needs the password'), { code: 'NEEDS_PASSWORD' })
      cands = [d]
    } else if (password) {
      cands = real.filter((d) => d.kind === 'password')
      if (!cands.length && !p.pwd) {
        throw Object.assign(new Error('this profile does not open with a password alone: use its security key'), { code: 'NEEDS_SECURITY_KEY' })
      }
    } else {
      throw Object.assign(new Error('nothing to open the profile with'), { code: 'NO_CREDENTIALS' })
    }
    const tries = frenar(p)
    let K = null
    for (const d of cands) {
      const k = doorKey(d, { password, secret })
      if (!k) continue
      try { K = Buffer.from(decryptText(d.wrapped, k), 'base64') } catch (_) { K = null }
      k.fill(0)
      if (K?.length === 32) break
      K = null
    }
    let legacy = false
    if (!K && password && p.pwd && !door) {
      const proof = p.pwd.v === 2 ? deriveScryptPwd(password, p.pwd.salt) : await derivePwd(password, p.pwd.salt, p.pwd.iter)
      if (proof === p.pwd.verifier) {
        if (!p.kdf) p.kdf = { v: 1, salt: b64(crypto.getRandomValues(new Uint8Array(32))) }
        K = scryptKey(password, p.kdf.salt)
        legacy = true
      }
    }
    if (!K) {
      p.tries = { n: tries.n + 1, at: Date.now() }
      save()
      throw Object.assign(new Error(door ? 'the key did not open this profile' : 'wrong password'), { code: 'WRONG_PASSWORD', tries: p.tries.n })
    }
    delete p.tries
    if (legacy) {
      // A PUERTA: la misma `K`, ahora en un sobre de la contraseña. El verificador y el salt de
      // derivación directa se van — de aquí en adelante la contraseña es una puerta más.
      p.doors = [...real, makeDoor(K, { kind: 'password', password }, { checkMin: false })]
      delete p.pwd; delete p.kdf
    }
    save()
    return K
  }

  const api = {
    get root () { return root },
    dirOf,
    list: () => data.profiles.map(entry),
    get: (id) => { const p = find(id); return p ? entry(p) : null },
    current: () => data.current,

    /**
     * Resuelve una referencia de la CLI: id exacto, o nombre (sin distinguir
     * mayúsculas). Un nombre ambiguo es un error explícito, no una elección al azar.
     */
    resolve (ref) {
      if (!ref) return data.current
      if (find(ref)) return ref
      const needle = String(ref).trim().toLowerCase()
      const hits = data.profiles.filter((p) => (p.name || '').toLowerCase() === needle)
      if (hits.length === 1) return hits[0].id
      if (hits.length > 1) throw new Error(`there are ${hits.length} profiles named "${ref}"; use its id (dotrino-vault profile ls)`)
      // POR PREFIJO. Desde que el id del perfil es el nombre de su carpeta —y ese sale de
      // la llave— es largo, y nadie va a teclear 24 caracteres para decir `--profile`. El
      // trozo que sí se lee y se reconoce es la huella de delante (`0571-465F`), que es la
      // misma que sale en `members`. Ambiguo se rechaza, no se adivina.
      // El id que tenía antes de que la carpeta se llamara como su llave (ver
      // `ensureNamedByKey`): un cliente abierto durante la actualización sigue usándolo.
      const viejo = data.profiles.find((p) => p.wasId && p.wasId.toLowerCase() === needle)
      if (viejo) return viejo.id
      const porPrefijo = data.profiles.filter((p) => p.id.toLowerCase().startsWith(needle))
      if (porPrefijo.length === 1) return porPrefijo[0].id
      if (porPrefijo.length > 1) throw new Error(`"${ref}" matches ${porPrefijo.length} profiles; give more of the id (dotrino-vault profile ls)`)
      throw new Error('profile does not exist: ' + ref)
    },

    /**
     * Migración desde la versión mono-perfil: los datos que vivían sueltos en la
     * raíz pasan a ser el primer perfil (mismo criterio que la migración del
     * navegador, que adopta la identidad vieja como «Perfil 1»). `transport.json`
     * se queda en la raíz: es del proceso, no de la identidad.
     */
    async migrate (mintKey) {
      if (data.profiles.length) return null
      const legacy = fs.existsSync(path.join(root, 'identity.json'))
      // EL PROVEEDOR DEL ENTORNO, y SOLO en una instalación nueva. Es lo que hace que un
      // contenedor levantado con `DOTRINO_KMS_KEY_ID` tenga su primer perfil ya con la
      // clave en el KMS, sin entrar a configurar nada.
      //
      // En una MIGRACIÓN no se toca, y el matiz importa: esos archivos ya están cifrados
      // con la clave de la máquina, así que ponerles ahora un proveedor distinto los
      // dejaría ilegibles —el guardia lo pararía, pero el usuario se quedaría con una
      // bóveda que no arranca tras actualizar—. Ahí se migra con `atrest rekey`, a la vista.
      const dir = api.stage({ fromEnv: !legacy })
      if (legacy) {
        for (const f of LEGACY_FILES) {
          const from = path.join(root, f)
          if (fs.existsSync(from)) { try { fs.renameSync(from, path.join(dir, f)) } catch (_) {} }
        }
        // peers namespaceados por el multi-perfil interno de @dotrino/identity
        for (const f of fs.readdirSync(root)) {
          if (/^peers\..+\.json$/.test(f)) { try { fs.renameSync(path.join(root, f), path.join(dir, f)) } catch (_) {} }
        }
      }
      try {
        // Al migrar, la llave ya existe y esto solo la lee; en una instalación nueva, la crea.
        const pub = await mintKey(dir)
        // «Perfil 1» tanto al migrar como en una instalación nueva: es un nombre que
        // el dueño puede cambiar, y evita que la CLI salude con «(sin nombre)».
        const p = await api.commit(dir, 'Perfil 1', { pub })
        data.current = p.id
        save()
        return { id: p.id, migrated: legacy }
      } catch (e) {
        // En una instalación NUEVA no hay nada que perder y la carpeta de paso se va. En
        // una MIGRACIÓN sí lo hay —los archivos del dueño ya están dentro—, así que se
        // queda donde está y se dice en voz alta: borrarla sería borrar su bóveda.
        if (!legacy) { try { fs.rmSync(dir, { recursive: true, force: true }) } catch (_) {} }
        else e.message += ` (your data is safe in ${dir}; it could not be given its final name)`
        throw e
      }
    },

    /**
     * Crea un perfil. Con `adopt: true` nace **para adoptar la cuenta de un aparato**
     * (camino A): la bóveda le hace sitio, pero la cuenta —el `profileId`, la reputación,
     * lo ya firmado— la trae el dispositivo. La marca la consume `startVault`, que se la
     * pasa a la identidad (`prepareForAdoption`); sin ella, adoptar una cuenta ajena se
     * leería como pisar una cuenta con datos y se rechazaría, que es lo que tiene que
     * pasar cuando nadie lo pidió.
     */
    /**
     * `kek`: el proveedor de la clave del disco, si el perfil tiene que NACER con él.
     *
     * Se escribe aquí y no después porque ese es justo el momento que importa: el
     * directorio existe y todavía no hay un solo byte dentro. La maestra que genere
     * `open()` un instante más tarde ya nace bajo esa clave y NUNCA existe bajo otra.
     *
     * Migrar un perfil que ya tiene identidad NO da esto, y por eso no se ofrece como
     * si lo diera: su maestra ya se escribió bajo la clave vieja, y una copia del disco
     * anterior a la migración la sigue abriendo para siempre. Un perfil con raíz en el
     * KMS **nace** así (dueño, 2026-08-30).
     */
    stage ({ kek = null, fromEnv = true } = {}) {
      const dir = path.join(root, 'p', stagingName())
      ensureDir(dir)
      // Sin `--kms` explícito, manda el entorno: es lo que permite levantar un contenedor
      // con KMS pasando variables, sin entrar a escribir un JSON dentro. Solo al CREAR:
      // un perfil que ya existe manda con su `atrest.json`.
      kek = kek || (fromEnv ? configFromEnv() : null)
      if (kek) {
        // Comprobar ANTES de dejar rastro: un KMS que no responde no puede dejar a
        // medio crear un perfil cuya maestra no se va a poder volver a abrir.
        try {
          probeKek(dir, kek)
          writeKekConfig(dir, kek)
        } catch (e) {
          try { fs.rmSync(dir, { recursive: true, force: true }) } catch (_) {}
          throw e
        }
      }
      return dir
    },

    /**
     * La carpeta de paso ya tiene su llave: se le pone SU nombre y entra en el registro.
     * El `id` del perfil ES el nombre de su carpeta, y sale de la llave (`keyDirName`).
     */
    async commit (staging, name, { adopt = false, pub } = {}) {
      if (!pub) throw new Error('cannot name the folder: the key is missing')
      const id = await keyDirName(pub)
      const dest = dirOf(id)
      // Esa llave ya tiene carpeta. No es un choque de nombres: es la MISMA llave dos
      // veces, que es justo lo que este esquema existe para que no pase.
      if (fs.existsSync(dest)) {
        try { fs.rmSync(staging, { recursive: true, force: true }) } catch (_) {}
        throw Object.assign(new Error('that key already has a folder here: ' + id), { code: 'key-exists' })
      }
      fs.renameSync(staging, dest)
      data.profiles.push({ id, name: cleanName(name), createdAt: Date.now(), ...(adopt ? { adopt: true } : {}) })
      if (!data.current) data.current = id
      save()
      return entry(find(id))
    },

    /**
     * Crea un perfil entero: hace el sitio, deja que `mintKey` acuñe la llave dentro y
     * mueve la carpeta a su nombre. `mintKey(dir)` devuelve la pública, y es cosa de quien
     * llama porque generar una identidad no es asunto del registro.
     */
    async add (name, { adopt = false, kek = null, mintKey } = {}) {
      if (typeof mintKey !== 'function') throw new Error('add() needs mintKey to know whose folder it is')
      const staging = api.stage({ kek })
      try {
        const pub = await mintKey(staging)
        return await api.commit(staging, name, { adopt, pub })
      } catch (e) {
        // Nada a medias: la carpeta de paso se va con el intento fallido.
        try { fs.rmSync(staging, { recursive: true, force: true }) } catch (_) {}
        throw e
      }
    },

    /**
     * PONERLE A UNA CARPETA VIEJA EL NOMBRE DE SU LLAVE.
     *
     * Es toda la migración: mover la data a la carpeta que le toca. Se hace con la
     * identidad CERRADA —antes de abrirla—, porque la identidad se queda con la ruta como
     * texto y renombrar por debajo la deja escribiendo en una carpeta que ya no existe.
     *
     * De quién es la carpeta se sabe por la marca (`key.json`); si no la tiene —una
     * instalación anterior a que existiera— se abre un momento solo para preguntárselo.
     */
    async ensureNamedByKey (id, mintKey) {
      const dir = dirOf(id)
      if (!fs.existsSync(dir)) return id
      let pub = keyOwnerOf(dir)
      if (!pub && typeof mintKey === 'function') {
        try { pub = await mintKey(dir) } catch (_) { return id }
      }
      if (!pub) return id
      const quiere = await keyDirName(pub)
      if (quiere === id) return id
      if (fs.existsSync(dirOf(quiere))) {
        throw Object.assign(new Error(`cannot rename ${id}: ${quiere} already exists`), { code: 'key-exists' })
      }
      fs.renameSync(dir, dirOf(quiere))
      const p = find(id)
      if (p) {
        p.id = quiere
        // EL NOMBRE VIEJO SE RECUERDA. Quien tenía una consola o una TUI abierta durante
        // la actualización sigue pidiendo por el id de antes, y sin esto cada petición
        // suya contestaba «ese perfil no existe» —que es verdad y no ayuda nada—. Se
        // traduce en `resolve`, así que el cliente viejo sigue funcionando hasta que se
        // reinicie, que es cuando dejará de preguntarlo.
        p.wasId = id
      }
      if (data.current === id) data.current = quiere
      if (unlocked.has(id)) { unlocked.set(quiere, unlocked.get(id)); unlocked.delete(id) }
      if (llaves.has(id)) { llaves.set(quiere, llaves.get(id)); llaves.delete(id) }
      save()
      return quiere
    },

    /** Quita la marca de «nació para adoptar» (ya adoptó, o se canceló). */
    clearAdopt (id) {
      const p = find(id)
      if (p?.adopt) { delete p.adopt; save() }
      return !!p
    },

    rename (id, name) {
      const p = assertExists(id)
      api.assertUnlocked(id)
      p.name = cleanName(name)
      save()
      return entry(p)
    },

    setCurrent (id) { assertExists(id); data.current = id; save(); return entry(find(id)) },

    /** Borra el perfil y TODOS sus datos (incluida su maestra). Irreversible. */
    remove (id) {
      const p = assertExists(id)
      if (data.profiles.length <= 1) throw new Error('cannot delete the only profile')
      api.assertUnlocked(id)
      data.profiles = data.profiles.filter((x) => x.id !== id)
      if (data.current === id) data.current = data.profiles[0].id
      save()
      unlocked.delete(id)
      olvidar(id)
      try { fs.rmSync(dirOf(id), { recursive: true, force: true }) } catch (_) {}
      return { id, name: p.name || '' }
    },

    // ----- candado -----

    isProtected: (id) => { const p = find(id); return !!p && isProtected(p) },
    isLocked: (id) => { const p = find(id); return !!p && isProtected(p) && !isOpen(id) },
    /** Cuánto dura abierto el candado sin usarse (ms). 0 = no se cierra solo. */
    get autoLockMs () { return autoLockMs },
    /**
     * «Se acaba de usar»: estira el plazo del bloqueo automático. Lo llama la consola
     * al atender CADA petición suya, y solo eso cuenta como uso: que un aparato pida su
     * configuración no abre nada ni alarga nada, porque el candado no es suyo.
     * Devuelve si el perfil estaba abierto (a uno cerrado no hay nada que estirarle).
     */
    touch (id) {
      if (!isOpen(id)) return false
      open(id)
      return true
    },
    assertUnlocked (id) {
      if (api.isLocked(id)) throw Object.assign(new Error('profile locked: unlock it first (dotrino-vault unlock)'), { code: 'PROFILE_LOCKED' })
    },

    // ----- LAS PUERTAS (`docs/llaves-de-hardware.md` §2bis) -----
    //
    // La llave del perfil (`K`) es UNA y NO CAMBIA: con ella van selladas la maestra, la copia
    // de recuperación de los secretos y las contraseñas. Lo que cambia son las PUERTAS, y cada
    // una es un sobre de `K`: contraseña, YubiKey con toque, YubiKey sin toque, o YubiKey MÁS
    // contraseña. Abre cualquiera. Poner o quitar una puerta no vuelve a sellar nada.
    //
    // Antes `K` SALÍA de la contraseña, y cambiarla —o quitarla— cambiaba `K` sin volver a
    // sellar la maestra: después de reiniciar quedaba cerrada con una llave que ya no existía
    // (reproducido el 2026-10-05). Con puertas eso no puede pasar.

    /** Las puertas, sin nada secreto: tipo, nombre y lo que hace falta para pedirle a la llave. */
    doors (id) { return publicDoors(assertExists(id)) },

    /**
     * La llave del perfil a partir de credenciales, SIN abrirlo. Abierto, una copia de la que
     * está en memoria. Pasa por el mismo freno de intentos que abrir.
     */
    async keyWith (id, creds = {}) {
      const p = assertExists(id)
      if (isOpen(id) && llaves.get(id)) return new Uint8Array(llaves.get(id))
      return new Uint8Array(await resolveK(p, normCreds(creds)))
    },

    /** Compatibilidad: la llave del perfil con la contraseña. Es `keyWith({ password })`. */
    async adminKey (id, password) { return api.keyWith(id, { password }) },

    /**
     * ABRIR. `creds`: la contraseña (texto, por compatibilidad) o `{ password, door, secret }`,
     * donde `secret` son los bytes que devolvió la llave de hardware para la puerta `door`.
     */
    async unlock (id, creds) {
      const p = assertExists(id)
      if (!isProtected(p)) { open(id); return { ok: true, locked: false } }
      const K = await resolveK(p, normCreds(creds))
      open(id)
      // La llave se queda mientras el candado esté abierto: es lo que permite envolverle
      // su cajón a un servicio que se enrola AHORA, sin volver a pedir la frase.
      llaves.set(id, new Uint8Array(K))
      K.fill(0)
      return { ok: true, locked: false }
    },

    /**
     * La llave del perfil para PONERLE UNA PUERTA. Si el perfil todavía no tiene (nunca tuvo
     * candado), se estrena una al azar y `fresh` lo dice: quien llama tiene que volver a
     * sellar con ella lo que estaba bajo la llave de la máquina (`manager.addDoor`).
     */
    ensureKey (id, { password = null } = {}) {
      const p = assertExists(id)
      if (hasKey(p)) {
        api.assertUnlocked(id)
        const K = api.openKey(id)
        if (!K) throw Object.assign(new Error('the profile key is not in memory: unlock the profile first'), { code: 'PROFILE_LOCKED' })
        return { K, fresh: false }
      }
      // LA DE ANTES, SI QUEDÓ SU SALT. Un perfil al que se le quitó la contraseña antes de las
      // puertas tiene la maestra sellada con `scrypt(aquella, kdf.salt)`: poniendo la MISMA
      // contraseña se recupera. Si no era esa, `manager.addDoor` lo ve (la maestra no abre) y
      // no guarda nada.
      const K = p.kdf?.salt && password
        ? new Uint8Array(scryptKey(password, p.kdf.salt))
        : new Uint8Array(crypto2.randomBytes(32))
      llaves.set(id, K)
      open(id)
      return { K, fresh: true }
    },

    /** Deshace un `ensureKey` fresco que no llegó a tener puerta. */
    dropFreshKey (id) {
      const p = find(id)
      if (p && !hasKey(p)) { unlocked.delete(id); olvidar(id) }
    },

    /**
     * Pone una puerta. `spec`:
     *   { kind: 'password', password }                        — sustituye a la contraseña que hubiera
     *   { kind: 'fido2', credId, hsalt, secret, label, password? }
     *   { kind: 'chalresp', challenge, serial, secret, label, password? }
     * Con `password` en una de hardware, hacen falta las DOS cosas para abrir por ella.
     */
    /**
     * Fabrica la puerta SIN guardarla: así quien llama comprueba que es válida (contraseña con
     * el mínimo, llave que devolvió algo) antes de sellar nada con esa llave.
     */
    prepareDoor (id, spec) {
      assertExists(id)
      const K = api.openKey(id)
      if (!K) throw Object.assign(new Error('unlock the profile first'), { code: 'PROFILE_LOCKED' })
      return makeDoor(K, spec)
    },

    addDoor (id, spec) {
      const p = assertExists(id)
      const K = api.openKey(id)
      if (!K) throw Object.assign(new Error('unlock the profile first'), { code: 'PROFILE_LOCKED' })
      const door = spec?.prepared || makeDoor(K, spec)
      let doors = (p.doors || []).filter((d) => d.kind !== 'machine')
      // UNA contraseña por perfil: poner otra la sustituye, también a la de antes de las puertas.
      if (door.kind === 'password') { doors = doors.filter((d) => d.kind !== 'password'); delete p.pwd }
      // El salt de derivación directa solo sirve para recuperar (ver `ensureKey`); con la llave
      // ya en una puerta, sobra.
      delete p.kdf
      p.doors = [...doors, door]
      delete p.tries
      save()
      // Si la llave venía de la de la máquina (perfil sin candado), ahora es la del perfil
      // ABIERTO: tiene que estar donde la busca `openKey` con el candado puesto.
      if (!llaves.get(id)) llaves.set(id, new Uint8Array(K))
      open(id)
      return publicDoor(door)
    },

    /**
     * Quita una puerta (por id) o la contraseña (`'password'`). Si no queda ninguna, el perfil
     * se queda SIN candado: `K` pasa a guardarse con la llave de esta máquina, igual que el
     * resto del disco, y se abre sola. Lo sellado con `K` sigue abriendo — no se toca nada.
     */
    removeDoor (id, which) {
      const p = assertExists(id)
      api.assertUnlocked(id)
      const K = api.openKey(id)
      if (!K) throw Object.assign(new Error('unlock the profile first'), { code: 'PROFILE_LOCKED' })
      const before = realDoors(p).length + (p.pwd ? 1 : 0)
      if (which === 'password') {
        p.doors = (p.doors || []).filter((d) => d.kind !== 'password')
        delete p.pwd; delete p.kdf
      } else {
        if (!(p.doors || []).some((d) => d.id === which && d.kind !== 'machine')) {
          throw Object.assign(new Error('that door does not exist: ' + which), { code: 'NO_SUCH_DOOR' })
        }
        p.doors = p.doors.filter((d) => d.id !== which)
      }
      const removed = before - realDoors(p).length
      if (!realDoors(p).length) {
        p.doors = [{ id: newDoorId(), kind: 'machine', createdAt: Date.now(), wrapped: encryptText(b64(K), Buffer.from(kekFor(dirOf(id)))) }]
        // Sin candado no hay nada que abrir a distancia.
        delete p.kdf2
      }
      save()
      open(id)
      return { removed, protected: isProtected(p) }
    },

    // ----- LA SEGUNDA CONTRASEÑA: la del admin (`docs/abrir-a-distancia.md`) -----
    //
    // DOS PUERTAS AL MISMO SITIO. La llave del perfil sale de `scrypt(principal, p.kdf.salt)`
    // y es lo que destapa la maestra. Una segunda contraseña NO puede derivar una llave
    // distinta —tiene que llegar a la misma—, así que lo que se guarda es **una copia de esa
    // llave, cifrada con lo que sale de la secundaria**. Es el mismo patrón que los cajones:
    // varios sobres, un destinatario cada uno.
    //
    // EL MOLINO LO HACE QUIEN LLAMA, no esto. Aquí entra `derivada` ya calculada, y hay dos
    // motivos: la bóveda nunca llega a ver la contraseña del admin, y adivinar le cuesta el
    // scrypt AL QUE PRUEBA en vez de costarle CPU a la bóveda (que además sería una forma de
    // ahogarla). El freno sigue contando los fallos igual — ver `frenar`.
    //
    // Y por eso `derivada` VALE TANTO COMO LA CONTRASEÑA: quien la capture abre igual. Viaja
    // cifrada a una llave efímera de la bóveda y la petición va firmada por un aparato del
    // acta; esas dos cosas son las que la protegen, no el hecho de estar derivada.

    /**
     * Los parámetros para que el admin derive EXACTAMENTE igual. Son públicos: un salt no es
     * un secreto y ya vive en el disco junto a los datos. `null` si este perfil no tiene
     * segunda contraseña — entonces abrir a distancia sencillamente no está disponible.
     */
    secondaryParams (id, { mint = false } = {}) {
      const p = find(id)
      if (!p) return null
      // `mint`: acuña el salt si todavía no hay ninguno. Lo pide QUIEN LA PONE, para poder
      // derivar una sola vez con el salt definitivo — si no, habría que derivar, guardar, y
      // volver a derivar con el salt que salió, que es como lo escribí primero y era torpe.
      if (!p.kdf2) {
        if (!mint) return null
        p.kdf2 = { v: 1, salt: b64(crypto.getRandomValues(new Uint8Array(32))), wrapped: null }
        save()
      }
      return { salt: p.kdf2.salt, ...SCRYPT }
    },

    /** ¿Tiene puesta la del admin? Es estado, y se enseña donde se administra. */
    hasSecondary: (id) => !!find(id)?.kdf2?.wrapped,

    /**
     * Pone o cambia la contraseña del admin. **Exige el perfil ABIERTO**, porque lo que se
     * guarda es la llave del perfil y esa solo está en memoria con el candado descorrido.
     * Es lo correcto además de lo posible: ponerla es una decisión del dueño, y el dueño
     * acaba de teclear la principal.
     */
    setSecondary (id, derivada) {
      const p = assertExists(id)
      if (!isProtected(p)) throw Object.assign(new Error('this profile has no lock: there is nothing to open remotely'), { code: 'NO_PASSWORD' })
      const llave = api.openKey(id)
      if (!llave) throw Object.assign(new Error('open the profile first (dotrino-vault unlock)'), { code: 'PROFILE_LOCKED' })
      if (!(derivada instanceof Uint8Array) || derivada.length !== 32) throw new Error('the admin key must be 32 bytes')
      const salt = p.kdf2?.salt || b64(crypto.getRandomValues(new Uint8Array(32)))
      p.kdf2 = { v: 1, salt, wrapped: encryptText(b64(llave), Buffer.from(derivada)) }
      save()
      return { ok: true }
    },

    /** La quita. Revocar es borrar el sobre: al instante y sin tocar la principal. */
    clearSecondary (id) {
      const p = assertExists(id)
      if (!p.kdf2?.wrapped) { if (p.kdf2) { delete p.kdf2; save() } ; return { ok: true, had: false } }
      delete p.kdf2
      save()
      return { ok: true, had: true }
    },

    /**
     * ABRE CON LA DEL ADMIN. Recibe la derivada, descifra el sobre y saca la llave del
     * perfil: de ahí para abajo el estado es idéntico a `unlock`, porque es la misma llave.
     *
     * No hay verificador aparte y no hace falta: AES-GCM autentica, así que una derivada
     * equivocada **no descifra**, y eso ES la comprobación.
     *
     * Comparte el contador de `unlock` (`frenar`): probar por aquí frena allá y al revés.
     */
    async openWithSecondary (id, derivada) {
      const p = assertExists(id)
      if (!p.kdf2?.wrapped) throw Object.assign(new Error('this profile has no admin password'), { code: 'NO_SECONDARY' })
      const tries = frenar(p)
      let llave = null
      try { llave = Buffer.from(decryptText(p.kdf2.wrapped, Buffer.from(derivada)), 'base64') } catch (_) { llave = null }
      if (!llave || llave.length !== 32) {
        p.tries = { n: tries.n + 1, at: Date.now() }
        save()
        throw Object.assign(new Error('wrong admin password'), { code: 'WRONG_PASSWORD', tries: p.tries.n })
      }
      delete p.tries
      save()
      open(id)
      llaves.set(id, new Uint8Array(llave))
      return { ok: true, locked: false }
    },

    lock (id) { assertExists(id); unlocked.delete(id); olvidar(id); return { ok: true, locked: api.isLocked(id) } },

    /**
     * La llave del perfil ABIERTO, o `null`. Es lo que hace que «la bóveda está abierta»
     * signifique algo más que una bandera: con ella se envuelve la llave de un cajón sin
     * volver a pedir la frase. Cerrado —o nunca abierto— devuelve `null` y quien llame
     * tendrá que pedirla, que es exactamente el comportamiento de antes.
     */
    openKey (id) {
      if (isOpen(id)) return llaves.get(id) || null
      // SIN CANDADO PERO CON LLAVE: un perfil al que se le quitó la última puerta. Su `K` vive
      // bajo la llave de la máquina y se abre sola, como el resto del disco.
      const p = find(id)
      const m = p && !isProtected(p) ? (p.doors || []).find((d) => d.kind === 'machine') : null
      if (!m) return null
      if (!porMaquina.has(id)) {
        const K = Buffer.from(decryptText(m.wrapped, Buffer.from(kekFor(dirOf(id)))), 'base64')
        if (K.length !== 32) throw Object.assign(new Error('the profile key under this machine key is malformed'), { code: 'BAD_PROFILE_KEY' })
        porMaquina.set(id, new Uint8Array(K))
      }
      return porMaquina.get(id)
    },

    /**
     * Pone o cambia la contraseña (la puerta `password`). Atajo de `ensureKey` + `addDoor`: si
     * el perfil no tenía llave se estrena una, y abrirlo después sella con ella la maestra y la
     * copia de recuperación (`takeMasterKey`, `migrarRecuperacionALaFrase`). El camino completo,
     * que vuelve a sellar en el acto, es `manager.addDoor`.
     */
    async setPassword (id, password) {
      const { fresh } = api.ensureKey(id)
      try { api.addDoor(id, { kind: 'password', password }) } catch (e) { if (fresh) api.dropFreshKey(id); throw e }
      return entry(find(id))
    },

    /** Quita la contraseña. Exige el perfil abierto. */
    removePassword (id) {
      api.removeDoor(id, 'password')
      return entry(find(id))
    }
  }

  return api
}
