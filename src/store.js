/**
 * Store del árbol de contenidos y los ajustes del vault.
 *
 * **Desde 0.56 esto es un REGISTRO DE OPERACIONES, no un JSON que se reescribe.** El
 * cambio viene de una idea del dueño (2026-08-30): varias bóvedas sobre un mismo dato,
 * cada una distinguiendo lo suyo. Con un archivo mutable eso no se puede — dos escritores
 * y el segundo borra al primero en silencio, aunque las dos escrituras estén firmadas.
 *
 * Ahora: cada bóveda **añade** a su propio registro (`log/<huella>.jsonl`, ver
 * `lib/src/oplog.js`) y el estado se **proyecta** leyéndolos todos en un orden que las dos
 * calculan igual. `vault.json` deja de ser la verdad; la verdad es el registro.
 *
 * Lo que eso cambia para quien llama: **escribir es asíncrono** (hay que firmar la
 * entrada). Leer sigue siendo síncrono, contra la vista que se armó al abrir.
 *
 * Sigue **cifrado en reposo** (`atrest.js`), pero POR LÍNEA: un archivo cifrado entero no
 * se puede ir añadiendo, que es todo el punto de un registro.
 *
 * NO guarda identidad, dispositivos ni certs: de eso se encarga `@dotrino/identity` en el
 * mismo dir. Aquí vive solo lo del usuario — el árbol y los ajustes.
 */
import fs from 'node:fs'
import path from 'node:path'
import { readJson } from './paths.js'
import { atRestFor } from './atrest.js'
import { openOpLog, project } from '../lib/src/oplog.js'
import { verifyDeviceSig } from '@dotrino/identity/capabilities'

const LEGACY = 'vault.json'

const newTree = () => ({ id: 'root', name: '', type: 'folder', children: [] })

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

/**
 * Cómo se aplica cada operación del árbol. Los ajustes los lleva `project` (última
 * escritura gana); esto es lo que el árbol añade encima.
 *
 * Las dos son **idempotentes y deterministas**, que es lo que hace falta para que dos
 * bóvedas lleguen al mismo sitio:
 *   · `add` con un id que ya está no duplica el nodo — repetir el registro no cambia nada.
 *   · `rm` de algo que no está no es un error, es que ya no está.
 *
 * Y la que hay que decidir a propósito: si una bóveda **borra** un nodo y la otra le
 * **cuelga un hijo** sin saberlo, gana quien vaya después en el orden común. Se puede
 * perder el hijo, pero **se pierde igual en todas**: convergen. La alternativa —conservar
 * al huérfano— dejaría un árbol distinto en cada máquina, que es peor.
 */
function aplicarArbol (estado, op) {
  if (op.op === 'add') {
    if (!estado.tree) estado.tree = newTree()
    if (op.node?.id && findNode(estado.tree, op.node.id)) return true   // ya está
    const padre = findNode(estado.tree, op.parent || 'root')
    if (!padre) return true                                            // el padre ya no existe
    if (!Array.isArray(padre.children)) padre.children = []
    padre.children.push(op.node)
    return true
  }
  if (op.op === 'rm') {
    const quitar = (n) => {
      if (!Array.isArray(n.children)) return false
      const i = n.children.findIndex((c) => c.id === op.id)
      if (i >= 0) { n.children.splice(i, 1); return true }
      return n.children.some(quitar)
    }
    if (estado.tree) quitar(estado.tree)
    return true
  }
  return false   // no es del árbol: que la trate `project` (los ajustes)
}

/**
 * @param {string} dir
 * @param {object} o
 * @param {object} o.identity  quien firma las entradas de ESTA bóveda. Cada escritor firma
 *                             las suyas con su propia llave; quién puede escribir lo dice
 *                             el acta, no este módulo.
 * @param {(pub:string)=>boolean} [o.puedeEscribir]  normalmente `Acta.memberCan(...)`.
 */
export async function openStore (dir, { identity, puedeEscribir = null } = {}) {
  const atRest = atRestFor(dir)
  const writer = identity?.me?.publickey || (await identity.signData({ op: 'whoami', ts: Date.now() })).publickey
  const log = openOpLog(dir, {
    writer,
    sign: async (body) => (await identity.signData(body)).signature,
    verify: verifyDeviceSig,
    atRest
  })

  let vista = { tree: newTree(), settings: {} }
  let lamport = 0

  async function releer () {
    const r = await log.replay({ puedeEscribir })
    lamport = r.lamport
    const estado = project(r.ops, { aplicar: aplicarArbol, inicial: { tree: newTree(), settings: {} } })
    // `project` deja los ajustes en la raíz del estado (es su semántica de `set`/`del`);
    // aquí se separan del árbol para no cambiar la forma que ya esperan los llamantes.
    const { tree, ...ajustes } = estado
    vista = { tree: tree || newTree(), settings: ajustes }
    return r
  }

  /**
   * MIGRACIÓN, y es de una sola vez: si hay un `vault.json` de antes, sus ajustes entran
   * como operaciones y el archivo se aparta con otro nombre. No se conserva leyéndolo
   * «por si acaso» — dos verdades para lo mismo se desincronizan y luego cada una dice
   * una cosa. El árbol no se importa porque nunca se escribió: `addNode`/`removeNode` no
   * los llamaba nadie (comprobado), así que lo único que había de verdad son los ajustes.
   */
  async function migrarSiHace () {
    const viejo = path.join(dir, LEGACY)
    if (!fs.existsSync(viejo)) return null
    const data = readJson(viejo, null, atRest)
    const ajustes = data?.settings && typeof data.settings === 'object' ? data.settings : {}
    for (const [k, v] of Object.entries(ajustes)) {
      if (v === undefined) continue
      const r = await log.append({ op: 'set', k, v }, { lamport: lamport + 1 })
      lamport = r.l
    }
    try { fs.renameSync(viejo, viejo + '.pre-oplog') } catch (_) {}
    return Object.keys(ajustes).length
  }

  await releer()
  const migrados = await migrarSiHace()
  if (migrados !== null) await releer()

  const escribir = async (op) => {
    const r = await log.append(op, { lamport: lamport + 1 })
    lamport = r.l
    await releer()
  }

  return {
    get raw () { return vista },
    /** Cuántos ajustes se trajeron del `vault.json` viejo (null si no había). */
    migrados,
    getTree () { return vista.tree },
    getNode (id) { return findNode(vista.tree, id || 'root') },
    addNode (parentId, node) { return escribir({ op: 'add', parent: parentId || 'root', node }).then(() => node) },
    removeNode (id) { return escribir({ op: 'rm', id }).then(() => !!id) },
    getSetting (k) { return vista.settings[k] },
    setSetting (k, v) { return escribir(v === undefined ? { op: 'del', k } : { op: 'set', k, v }) },
    /** Todos los ajustes (copia). Para quien necesita buscar por prefijo. */
    listSettings () { return { ...vista.settings } },
    /** Vuelve a leer los registros. Lo usa quien acaba de recibir los de otra bóveda. */
    refresh: releer
  }
}
