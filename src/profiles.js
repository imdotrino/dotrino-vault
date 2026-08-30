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
import { atRestFor, migrateFile, kekFor } from './atrest.js'

const REGISTRY = 'profiles.json'
const PWD_ITER = 300000 // PBKDF2 del verificador v1 (heredado); v2 usa scrypt
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
  return b64(crypto2.scryptSync(String(password || ''), salt, 32, { N: 16384, r: 8, p: 1 }))
}

/** PBKDF2-SHA256 → verificador base64 (v1, heredado). */
async function derivePwd (password, saltB64, iter) {
  const salt = Buffer.from(saltB64, 'base64')
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(password)), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, km, 256)
  return b64(bits)
}

const newId = () => 'p' + crypto.randomUUID().slice(0, 8)
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
  try { migrateFile(file, kekFor(root)) } catch (_) {}
  const atRest = atRestFor(root)
  let data = readJson(file, null, atRest)
  if (!data || !Array.isArray(data.profiles)) data = { v: 1, current: null, profiles: [] }
  const save = () => writeJson(file, data, atRest)

  // Perfiles DESBLOQUEADOS en esta ejecución del daemon (en memoria: un reinicio
  // vuelve a bloquear, igual que cerrar la pestaña en el navegador), cada uno con la
  // hora a la que se cierra solo si nadie lo usa (ver AUTO_LOCK_MS).
  const unlocked = new Map() // id -> vence (ms epoch)

  /** ¿Sigue abierto? Vence al MIRARLO, así que no hace falta ningún temporizador. */
  const isOpen = (id) => {
    const until = unlocked.get(id)
    if (until == null) return false
    if (autoLockMs > 0 && Date.now() >= until) {
      unlocked.delete(id)
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
    protected: !!p.pwd,
    locked: !!p.pwd && !isOpen(p.id),
    // Hasta cuándo sigue abierto si nadie lo toca. Es DATO: la consola lo enseña para
    // que el cierre no llegue por sorpresa.
    ...(p.pwd && isOpen(p.id) && autoLockMs > 0 ? { until: unlocked.get(p.id) } : {}),
    current: p.id === data.current,
    // Nació para adoptar la cuenta de un aparato (camino A) y todavía no lo ha hecho.
    ...(p.adopt ? { adopt: true } : {})
  })

  function assertExists (id) {
    const p = find(id)
    if (!p) throw new Error('profile does not exist: ' + id)
    return p
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
      throw new Error('profile does not exist: ' + ref)
    },

    /**
     * Migración desde la versión mono-perfil: los datos que vivían sueltos en la
     * raíz pasan a ser el primer perfil (mismo criterio que la migración del
     * navegador, que adopta la identidad vieja como «Perfil 1»). `transport.json`
     * se queda en la raíz: es del proceso, no de la identidad.
     */
    migrate () {
      if (data.profiles.length) return null
      const legacy = fs.existsSync(path.join(root, 'identity.json'))
      const id = newId()
      const dir = dirOf(id)
      ensureDir(dir)
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
      // «Perfil 1» tanto al migrar como en una instalación nueva: es un nombre que
      // el dueño puede cambiar, y evita que la CLI salude con «(sin nombre)».
      data.profiles.push({ id, name: 'Perfil 1', createdAt: Date.now() })
      data.current = id
      save()
      return { id, migrated: legacy }
    },

    /**
     * Crea un perfil. Con `adopt: true` nace **para adoptar la cuenta de un aparato**
     * (camino A): la bóveda le hace sitio, pero la cuenta —el `profileId`, la reputación,
     * lo ya firmado— la trae el dispositivo. La marca la consume `startVault`, que se la
     * pasa a la identidad (`prepareForAdoption`); sin ella, adoptar una cuenta ajena se
     * leería como pisar una cuenta con datos y se rechazaría, que es lo que tiene que
     * pasar cuando nadie lo pidió.
     */
    add (name, { adopt = false } = {}) {
      const id = newId()
      ensureDir(dirOf(id))
      data.profiles.push({ id, name: cleanName(name), createdAt: Date.now(), ...(adopt ? { adopt: true } : {}) })
      if (!data.current) data.current = id
      save()
      return entry(find(id))
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
      try { fs.rmSync(dirOf(id), { recursive: true, force: true }) } catch (_) {}
      return { id, name: p.name || '' }
    },

    // ----- candado -----

    isProtected: (id) => !!find(id)?.pwd,
    isLocked: (id) => { const p = find(id); return !!p?.pwd && !isOpen(id) },
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
      if (api.isLocked(id)) throw new Error('profile locked: unlock it with your password (dotrino-vault unlock)')
    },

    /**
     * La llave con la que se abre la copia MAESTRA de los secretos, derivada de la
     * contraseña del perfil. Va por operación: quien la pide la usa y la suelta.
     *
     * Es scrypt (mismo coste que `machineKey`) y NO reusa el verificador del candado:
     * ese es PBKDF2 y vive en claro en este mismo archivo, así que sería el camino
     * barato para atacarla. Aquí la prueba de que es correcta es el tag AES-GCM del
     * propio sobre — si no cuadra, la contraseña no era.
     */
    async adminKey (id, password) {
      const p = find(id)
      if (!p) throw new Error('profile not found')
      if (!p.kdf) {
        p.kdf = { v: 1, salt: b64(crypto.getRandomValues(new Uint8Array(32))) }
        save()
      }
      const salt = Buffer.from(p.kdf.salt, 'base64')
      return new Uint8Array(crypto2.scryptSync(String(password || ''), salt, 32, { N: 16384, r: 8, p: 1 }))
    },

    async unlock (id, password) {
      const p = assertExists(id)
      if (!p.pwd) { open(id); return { ok: true, locked: false } }
      // Freno de fuerza bruta (una contraseña corta se adivina probando): tras 5
      // fallos, espera exponencial (2^n s, tope 5 min) persistida en el registro.
      // Los fallos VIEJOS se olvidan (ver TRIES_FORGET_MS): si desde el último ha pasado
      // el rato, se empieza de cero. Así el freno sigue frenando una ráfaga —los intentos
      // seguidos se cuentan igual— pero no convierte un despiste de ayer en un vault que
      // ya no se abre.
      let tries = p.tries || { n: 0, at: 0 }
      if (tries.at && Date.now() - tries.at > TRIES_FORGET_MS) {
        tries = { n: 0, at: 0 }
        if (p.tries) { delete p.tries; save() }
      }
      const waitMs = tries.n >= 5 ? Math.min(2 ** (tries.n - 4) * 1000, 5 * 60 * 1000) : 0
      const left = tries.at + waitMs - Date.now()
      // Con CÓDIGO: la TUI es bilingüe y lo traduce, y la CLI puede decirlo con sus
      // palabras. Sin código, el rechazo llegaba como un texto suelto del daemon y era
      // indistinguible de «se volvió a pedir la contraseña porque sí».
      if (left > 0) {
        throw Object.assign(new Error(`too many tries: wait ${Math.ceil(left / 1000)} s`),
          { code: 'TOO_MANY_TRIES', waitSec: Math.ceil(left / 1000) })
      }
      const proof = p.pwd.v === 2
        ? deriveScryptPwd(password, p.pwd.salt)
        : await derivePwd(password, p.pwd.salt, p.pwd.iter)
      if (proof !== p.pwd.verifier) {
        p.tries = { n: tries.n + 1, at: Date.now() }
        save()
        throw Object.assign(new Error('wrong password'), { code: 'WRONG_PASSWORD', tries: p.tries.n })
      }
      // ASCENSO v1 → v2. Aquí, y solo aquí, se tiene la contraseña correcta en la mano:
      // es el momento de dejar de guardar el verificador barato. No cambia la
      // contraseña ni toca los secretos — el `adminKey` sale de `p.kdf`, que es otro.
      if (p.pwd.v !== 2) {
        const salt = b64(crypto.getRandomValues(new Uint8Array(16)))
        p.pwd = { v: 2, salt, verifier: deriveScryptPwd(password, salt) }
      }
      delete p.tries
      save()
      open(id)
      return { ok: true, locked: false }
    },

    lock (id) { assertExists(id); unlocked.delete(id); return { ok: true, locked: api.isLocked(id) } },

    /** Pone o cambia la contraseña. Cambiarla exige haber desbloqueado antes. */
    async setPassword (id, password) {
      const p = assertExists(id)
      api.assertUnlocked(id)
      if (!password || String(password).length < PWD_MIN) {
        throw Object.assign(new Error(`password must be at least ${PWD_MIN} characters: use several random words`),
          { code: 'PASSWORD_TOO_SHORT', min: PWD_MIN })
      }
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)))
      p.pwd = { v: 2, salt, verifier: deriveScryptPwd(password, salt) }
      delete p.tries
      save()
      open(id)
      return entry(p)
    },

    removePassword (id) {
      const p = assertExists(id)
      api.assertUnlocked(id)
      delete p.pwd
      delete p.tries
      save()
      open(id)
      return entry(p)
    }
  }

  return api
}
