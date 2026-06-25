/**
 * Store del árbol de contenidos del vault (`vault.json`). Versionado con
 * `schemaVersion` para que v2 pueda introducir cifrado en reposo sin migración
 * dolorosa. NO guarda identidad/dispositivos/certs: de eso se encarga
 * `@dotrino/identity` dentro del mismo dir (keypair, contactos, delegaciones,
 * revocaciones). Aquí vive solo lo del usuario: el árbol y los settings.
 */
import path from 'node:path'
import { readJson, writeJson } from './paths.js'

const SCHEMA_VERSION = 1

function newTree () {
  return { id: 'root', name: '', type: 'folder', children: [] }
}

function findNode (node, id) {
  if (!node) return null
  if (node.id === id) return node
  if (Array.isArray(node.children)) {
    for (const c of node.children) {
      const r = findNode(c, id)
      if (r) return r
    }
  }
  return null
}

export function openStore (dir) {
  const file = path.join(dir, 'vault.json')
  let data = readJson(file, null)
  if (!data || data.schemaVersion !== SCHEMA_VERSION) {
    data = { schemaVersion: SCHEMA_VERSION, tree: newTree(), settings: {} }
    writeJson(file, data)
  }
  const save = () => writeJson(file, data)

  return {
    get raw () { return data },
    getTree () { return data.tree },
    getNode (id) { return findNode(data.tree, id || 'root') },
    addNode (parentId, node) {
      const parent = findNode(data.tree, parentId || 'root')
      if (!parent) throw new Error('nodo padre no encontrado: ' + parentId)
      if (!Array.isArray(parent.children)) parent.children = []
      parent.children.push(node)
      save()
      return node
    },
    removeNode (id) {
      const remove = (node) => {
        if (!Array.isArray(node.children)) return false
        const i = node.children.findIndex((c) => c.id === id)
        if (i >= 0) { node.children.splice(i, 1); return true }
        return node.children.some(remove)
      }
      const ok = remove(data.tree)
      if (ok) save()
      return ok
    },
    getSetting (k) { return data.settings[k] },
    setSetting (k, v) { data.settings[k] = v; save() }
  }
}
