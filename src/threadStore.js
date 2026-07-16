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
 */
import path from 'node:path'
import { readJson, writeJson } from './paths.js'

const MAX_PER_THREAD = 1000

export function openThreadStore (dir) {
  const file = path.join(dir, 'threads.json')
  let data = readJson(file, null)
  if (!data || typeof data !== 'object') data = { v: 1, threads: {}, opens: {} }
  if (!data.threads) data.threads = {}
  if (!data.opens) data.opens = {}
  const save = () => writeJson(file, data)
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
    getStats () {
      const threads = {}
      for (const [k, arr] of Object.entries(data.threads)) threads[k] = { count: arr.length }
      return { threadCount: Object.keys(data.threads).length, threads, opensCount: Object.keys(data.opens).length }
    }
  }
  return { methods, raw: () => data }
}

/** Métodos del store que son de SOLO LECTURA (para decidir el scope necesario). */
export const STORE_READ_METHODS = new Set([
  'listThread', 'listThreadKeys', 'getThreadSummaries', 'getOpens', 'exportThreads', 'getStats', 'profileGet'
])

/**
 * Métodos que EDITAN el perfil del usuario (quién es: apodo, avatar, campos).
 * Son los únicos que el candado por contraseña bloquea (`vault.js`): el resto del
 * store —contenido de las apps— sigue disponible con el perfil bloqueado.
 */
export const PROFILE_EDIT_METHODS = new Set(['profileSet'])
