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
 * CONTRASEÑA (opcional, por perfil): es un VERIFICADOR PBKDF2 —mismo modelo que el
 * candado del navegador (`@dotrino/identity` vault/core.js)— NO cifra nada en reposo.
 * Y solo bloquea EDITAR el perfil: el daemon sigue firmando y sirviendo a los
 * dispositivos ya enrolados aunque el perfil esté bloqueado, para que un reinicio
 * del PC no deje las apps muertas hasta que alguien teclee la contraseña.
 * Protege contra que otro que se siente en la máquina —o un dispositivo enrolado—
 * te reescriba el perfil; NO contra quien pueda leer el disco (para eso hace falta
 * cifrado en reposo, ver `paths.js`).
 */
import fs from 'node:fs'
import path from 'node:path'
import { dataDir, ensureDir, readJson, writeJson } from './paths.js'

const REGISTRY = 'profiles.json'
const PWD_ITER = 300000 // mismo coste que el candado del navegador
const MAX_NAME = 40

/** Archivos de un perfil que en la versión mono-perfil vivían sueltos en la raíz. */
const LEGACY_FILES = ['identity.json', 'peers.json', 'vault.json', 'threads.json', 'secrets.json', 'activity.log']

const b64 = (buf) => Buffer.from(new Uint8Array(buf)).toString('base64')

/** PBKDF2-SHA256 → verificador base64 (byte-idéntico al del navegador). */
async function derivePwd (password, saltB64, iter) {
  const salt = Buffer.from(saltB64, 'base64')
  const km = await crypto.subtle.importKey('raw', new TextEncoder().encode(String(password)), 'PBKDF2', false, ['deriveBits'])
  const bits = await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: iter }, km, 256)
  return b64(bits)
}

const newId = () => 'p' + crypto.randomUUID().slice(0, 8)
const cleanName = (name) => String(name || '').slice(0, MAX_NAME)

export function openProfiles (root = dataDir()) {
  const file = path.join(root, REGISTRY)
  let data = readJson(file, null)
  if (!data || !Array.isArray(data.profiles)) data = { v: 1, current: null, profiles: [] }
  const save = () => writeJson(file, data)

  // Perfiles DESBLOQUEADOS en esta ejecución del daemon (en memoria: un reinicio
  // vuelve a bloquear, igual que cerrar la pestaña en el navegador).
  const unlocked = new Set()

  const find = (id) => data.profiles.find((p) => p.id === id) || null
  const dirOf = (id) => path.join(root, 'p', id)

  const entry = (p) => ({
    id: p.id,
    name: p.name || '',
    createdAt: p.createdAt || null,
    protected: !!p.pwd,
    locked: !!p.pwd && !unlocked.has(p.id),
    current: p.id === data.current
  })

  function assertExists (id) {
    const p = find(id)
    if (!p) throw new Error('el perfil no existe: ' + id)
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
      if (hits.length > 1) throw new Error(`hay ${hits.length} perfiles llamados "${ref}"; usa su id (dotrino-vault profile ls)`)
      throw new Error('el perfil no existe: ' + ref)
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

    add (name) {
      const id = newId()
      ensureDir(dirOf(id))
      data.profiles.push({ id, name: cleanName(name), createdAt: Date.now() })
      if (!data.current) data.current = id
      save()
      return entry(find(id))
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
      if (data.profiles.length <= 1) throw new Error('no se puede borrar el único perfil')
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
    isLocked: (id) => { const p = find(id); return !!p?.pwd && !unlocked.has(id) },
    assertUnlocked (id) {
      if (api.isLocked(id)) throw new Error('perfil bloqueado: desbloquéalo con tu contraseña (dotrino-vault unlock)')
    },

    async unlock (id, password) {
      const p = assertExists(id)
      if (!p.pwd) { unlocked.add(id); return { ok: true, locked: false } }
      // Freno de fuerza bruta (una contraseña corta se adivina probando): tras 5
      // fallos, espera exponencial (2^n s, tope 5 min) persistida en el registro.
      const tries = p.tries || { n: 0, at: 0 }
      const waitMs = tries.n >= 5 ? Math.min(2 ** (tries.n - 4) * 1000, 5 * 60 * 1000) : 0
      const left = tries.at + waitMs - Date.now()
      if (left > 0) throw new Error(`demasiados intentos: espera ${Math.ceil(left / 1000)} s`)
      const proof = await derivePwd(password, p.pwd.salt, p.pwd.iter)
      if (proof !== p.pwd.verifier) {
        p.tries = { n: tries.n + 1, at: Date.now() }
        save()
        throw new Error('contraseña incorrecta')
      }
      delete p.tries
      save()
      unlocked.add(id)
      return { ok: true, locked: false }
    },

    lock (id) { assertExists(id); unlocked.delete(id); return { ok: true, locked: api.isLocked(id) } },

    /** Pone o cambia la contraseña. Cambiarla exige haber desbloqueado antes. */
    async setPassword (id, password) {
      const p = assertExists(id)
      api.assertUnlocked(id)
      if (!password || String(password).length < 4) throw new Error('la contraseña debe tener al menos 4 caracteres')
      const salt = b64(crypto.getRandomValues(new Uint8Array(16)))
      p.pwd = { v: 1, salt, iter: PWD_ITER, verifier: await derivePwd(password, salt, PWD_ITER) }
      delete p.tries
      save()
      unlocked.add(id)
      return entry(p)
    },

    removePassword (id) {
      const p = assertExists(id)
      api.assertUnlocked(id)
      delete p.pwd
      delete p.tries
      save()
      unlocked.add(id)
      return entry(p)
    }
  }

  return api
}
