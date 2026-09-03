/**
 * Sub-store de HILOS + APERTURAS del vault (Fase 3: store centralizado).
 *
 * Espeja el modelo de datos de `@dotrino/store` (store.dotrino.com):
 *   threads: { [threadKey]: Entry[] }   (Entry tiene `id` + `ts`, opaco para el store)
 *   opens:   { [appId]: { count, ts } } (contador de "recientes" del hub)
 * para que un dispositivo emparejado pueda guardar su contenido EN el vault del
 * usuario (su propio servidor) en vez de —o además de— el IndexedDB del navegador.
 *
 * File-backed (`threads.json`), síncrono y simple (sin cuota/IndexedDB). Es el
 * backend autoritativo; el navegador usa su IndexedDB como caché y sincroniza.
 * **Cifrado en reposo** con la clave ligada a la máquina (`atrest.js`): aquí
 * vive el contenido de las apps y el perfil del usuario, que es exactamente lo
 * que el ecosistema promete que no queda en claro en ningún disco.
 */
import path from 'node:path'
import { readJson, writeJson } from './paths.js'
import { atRestFor } from './atrest.js'

const MAX_PER_THREAD = 1000

// DATOS SENSIBLES (F4): topes para que un dispositivo con `vault:store` no pueda
// llenar el disco de la bóveda. Son generosos para el uso real (unas contraseñas,
// notas, un documento corto) y ridículos para un abuso.
const MAX_SECURE_ITEMS = 2000
const MAX_SECURE_BLOB = 64 * 1024   // por campo sellado (meta y valor)

export function openThreadStore (dir) {
  const file = path.join(dir, 'threads.json')
  const atRest = atRestFor(dir)
  let data = readJson(file, null, atRest)
  if (!data || typeof data !== 'object') data = { v: 1, threads: {}, opens: {} }
  if (!data.threads) data.threads = {}
  if (!data.opens) data.opens = {}
  if (!data.secure) data.secure = {}
  const save = () => writeJson(file, data, atRest)
  save() // reescribe al abrir: cifra lo que venía en claro
  const trim = (arr) => { if (arr.length > MAX_PER_THREAD) arr.splice(0, arr.length - MAX_PER_THREAD) }

  const methods = {
    appendMessage ({ threadKey, entry }) {
      if (!threadKey || typeof threadKey !== 'string') throw new Error('threadKey required')
      if (!entry || typeof entry !== 'object') throw new Error('entry required')
      if (!entry.id) entry.id = crypto.randomUUID()
      if (!entry.ts) entry.ts = Date.now()
      const arr = data.threads[threadKey] || (data.threads[threadKey] = [])
      const i = arr.findIndex((e) => e.id === entry.id)
      if (i >= 0) arr[i] = { ...arr[i], ...entry }; else arr.push(entry)
      trim(arr); save(); return entry
    },
    listThread ({ threadKey, limit, before }) {
      if (!threadKey) return []
      let arr = data.threads[threadKey] || []
      if (typeof before === 'number') arr = arr.filter((e) => (e.ts || 0) < before)
      if (typeof limit === 'number' && limit > 0) arr = arr.slice(-limit)
      return arr
    },
    listThreadKeys () { return Object.keys(data.threads) },
    getThreadSummaries () {
      const out = {}
      for (const [k, arr] of Object.entries(data.threads)) out[k] = { lastEntry: arr.length ? arr[arr.length - 1] : null, count: arr.length }
      return out
    },
    removeThread ({ threadKey }) {
      const removed = data.threads[threadKey]?.length || 0
      delete data.threads[threadKey]; save(); return { removed }
    },
    removeMessage ({ threadKey, id }) {
      const arr = data.threads[threadKey] || []; const before = arr.length
      data.threads[threadKey] = arr.filter((e) => e.id !== id)
      if (data.threads[threadKey].length === 0) delete data.threads[threadKey]
      save(); return { removed: before - (data.threads[threadKey]?.length || 0) }
    },
    recordOpen ({ appId }) {
      if (!appId || typeof appId !== 'string') throw new Error('appId required')
      const prev = data.opens[appId]
      data.opens[appId] = { count: (prev?.count || 0) + 1, ts: Date.now() }
      save(); return data.opens[appId]
    },
    getOpens () { return { ...data.opens } },
    clearOpens () { data.opens = {}; save(); return { ok: true } },
    exportThreads () { return { threads: data.threads } },
    importThreads ({ threads, mode = 'merge' }) {
      if (!threads || typeof threads !== 'object') throw new Error('threads required')
      if (mode === 'replace') { data.threads = threads; save(); return { mode, count: Object.keys(threads).length } }
      for (const [k, arr] of Object.entries(threads)) {
        const cur = data.threads[k] || (data.threads[k] = [])
        const byId = new Map(cur.map((e) => [e.id, e]))
        for (const e of arr) { if (!e?.id) continue; const pr = byId.get(e.id); if (!pr || (e.ts || 0) > (pr.ts || 0)) byId.set(e.id, e) }
        data.threads[k] = Array.from(byId.values()).sort((a, b) => (a.ts || 0) - (b.ts || 0)); trim(data.threads[k])
      }
      save(); return { mode, count: Object.keys(data.threads).length }
    },
    // ----- PERFIL del usuario (me): el vault es la copia AUTORITATIVA -----
    // Cada dispositivo emparejado lo empuja al editarlo y lo jala al arrancar →
    // el mismo perfil (apodo/avatar/datos) en todos los dispositivos.
    profileSet ({ me }) {
      if (!me || typeof me !== 'object') throw new Error('me required')
      // nunca guardar llaves de dispositivo (son por-dispositivo)
      const { publickey, encryptionPubkey, ...content } = me
      data.profile = { ...content, updatedAt: content.updatedAt || Date.now() }
      save(); return { ok: true, updatedAt: data.profile.updatedAt }
    },
    profileGet () { return { me: data.profile || null } },

    // LOS DATOS DEL PERFIL EN SOBRES (`docs/datos-del-perfil.md`). Están aquí solo para
    // que el filtro de métodos los reconozca: los atiende `handleProfile` en `vault.js`,
    // antes de llegar a este store, porque su puerta es otra —`firma` y sin candado—.
    // Si alguna vez alguien los llamara por este camino, contestan que no en vez de
    // hacer algo a medias.
    profilePut () { throw new Error('profilePut is handled before the store: see handleProfile') },
    profileBundle () { throw new Error('profileBundle is handled before the store: see handleProfile') },
    profilePublic () { throw new Error('profilePublic is handled before the store: see handleProfile') },

    // ----- DATOS SENSIBLES del usuario (F4, docs/consola-remota.md §6) -----
    //
    // Contraseñas, notas, documentos: van al contenido del perfil, cifrados con la
    // CEK de la cuenta y accesibles con `vault:store` — el mismo camino que hilos y
    // perfil. NO tocan `secrets.json`: ese es el cajón de los SERVICIOS (proxy, geo),
    // acotado por CN y con clave ligada a la máquina. Mismo nombre coloquial, distinto
    // dueño.
    //
    // La bóveda guarda DOS SOBRES OPACOS por ficha y no abre ninguno:
    //   `meta` — lo que hace falta para pintar la lista (nombre, tipo, carpeta)
    //   `enc`  — el valor en sí, que solo viaja cuando abres la ficha
    // Los sella el dispositivo con la clave de contenido (`identity.sealContent`). Que
    // sean dos y no uno es lo que permite listar sin bajar todas las contraseñas, y que
    // el nombre («Banco») tampoco quede legible aquí.
    //
    // Alcance: esto es el ALMACÉN. Una app de contraseñas con generador y
    // autocompletado es otra cosa y no vive aquí.
    'secure.list' () {
      return Object.values(data.secure)
        .map(({ enc, ...rest }) => rest)   // el valor NO viaja al listar
        .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0))
    },
    'secure.get' ({ id }) {
      if (!id || typeof id !== 'string') throw new Error('id required')
      return data.secure[id] || null
    },
    'secure.put' ({ id, meta, enc }) {
      if (typeof enc !== 'string' || !enc) throw new Error('enc required (sealed value)')
      if (meta != null && typeof meta !== 'string') throw new Error('meta must be a sealed string')
      // Se comprueba el TAMAÑO, nunca el contenido: son sobres cerrados.
      if (enc.length > MAX_SECURE_BLOB || (meta || '').length > MAX_SECURE_BLOB) throw new Error('secure: item too large')
      const prev = id ? data.secure[id] : null
      if (!prev && Object.keys(data.secure).length >= MAX_SECURE_ITEMS) throw new Error('secure: too many items')
      const rec = {
        id: prev?.id || id || crypto.randomUUID(),
        ts: prev?.ts || Date.now(),
        updatedAt: Date.now(),
        meta: meta ?? prev?.meta ?? null,
        enc
      }
      data.secure[rec.id] = rec
      save()
      return { id: rec.id, updatedAt: rec.updatedAt }
    },
    'secure.del' ({ id }) {
      if (!id || typeof id !== 'string') throw new Error('id required')
      const had = !!data.secure[id]
      delete data.secure[id]
      if (had) save()
      return { removed: had ? 1 : 0 }
    },

    getStats () {
      const threads = {}
      for (const [k, arr] of Object.entries(data.threads)) threads[k] = { count: arr.length }
      return { threadCount: Object.keys(data.threads).length, threads, opensCount: Object.keys(data.opens).length, secureCount: Object.keys(data.secure).length }
    }
  }
  return { methods, raw: () => data }
}

/**
 * Métodos del store que son de SOLO LECTURA (para decidir el scope necesario).
 *
 * `secure.list`/`secure.get` NO están aquí a propósito, aunque sean lecturas: los datos
 * sensibles piden `vault:store` (doc §6), que es MÁS estricto que `vault:read`. Un
 * dispositivo al que solo le diste «leer» no lee tus contraseñas.
 */
export const STORE_READ_METHODS = new Set([
  'listThread', 'listThreadKeys', 'getThreadSummaries', 'getOpens', 'exportThreads', 'getStats', 'profileGet'
])

/**
 * Métodos que EDITAN el perfil del usuario (quién es: apodo, avatar, campos).
 * Son los únicos que el candado por contraseña bloquea (`vault.js`): el resto del
 * store —contenido de las apps— sigue disponible con el perfil bloqueado.
 */
export const PROFILE_EDIT_METHODS = new Set(['profileSet'])
