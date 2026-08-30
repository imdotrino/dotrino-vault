/**
 * oplog.js — UN REGISTRO POR ESCRITOR, para que N bóvedas escriban el mismo dato sin
 * pisarse.
 *
 * Nace de una idea del dueño (2026-08-30): *«pueden ser diez llaves y mientras el acta y
 * los sobres sean coherentes cada uno sabrá distinguir en una data única»*. Tiene razón —
 * con objetos firmados y autodescriptivos, varios escritores sobre un mismo almacén es un
 * problema resuelto. Lo que faltaba no eran las firmas: era **la forma del almacén**.
 *
 * Hoy `vault.json`, `threads.json` y compañía son JSON que se reescribe ENTERO. Dos
 * escritores y el segundo borra el cambio del primero, en silencio, aunque las dos
 * escrituras estén perfectamente firmadas. Una firma válida sobre un archivo que acaba de
 * pisar otro archivo válido sigue siendo pérdida de datos.
 *
 * LA IDEA, que es vieja y está bien entendida (un log de operaciones):
 *
 *   · **Un archivo por escritor** (`log/<huella>.jsonl`). Cada bóveda solo añade al SUYO,
 *     así que dos escrituras concurrentes no se tocan **por construcción**. No hace falta
 *     candado, y eso importa: el candado que hay hoy es un pid y no cruza contenedores.
 *   · **Cada entrada va firmada y encadenada** al anterior del mismo escritor (`prev`).
 *     Truncar o alterar el registro de alguien se nota; no hace falta confiar en el disco.
 *   · **Leer es fusionar**: se juntan todos los registros, se verifica cada entrada y se
 *     aplican en un orden que TODOS calculan igual. El JSON de siempre pasa a ser una
 *     proyección de esto, no la verdad.
 *
 * EL ORDEN, que es lo único delicado. Va por reloj de Lamport (`l`), no por hora:
 * `l = max(todos los que he visto) + 1`. Da causalidad —lo que se escribió sabiendo algo
 * va después de ese algo— y a igual `l` desempata la pubkey menor del escritor. Es
 * determinista y no depende de relojes, **la misma regla que ya gobierna el acta** y por
 * el mismo motivo escrito en `acta.js`: si dependiera de la hora, atrasar el reloj de una
 * máquina reescribiría el orden.
 *
 * `ts` se guarda, pero es INFORMATIVO. No se ordena por él. Nunca.
 *
 * QUIÉN PUEDE ESCRIBIR lo dice el acta, no este módulo: `replay` recibe un `puedeEscribir`
 * y descarta lo que venga de quien el acta no reconozca. Así el registro hereda la misma
 * autoridad que todo lo demás en vez de inventarse una.
 */
import fs from 'node:fs'
import path from 'node:path'
import crypto from 'node:crypto'

/** Subdirectorio donde viven los registros. Uno por escritor. */
export const LOG_DIR = 'log'

const hex = (b) => Buffer.from(b).toString('hex')
const hashOf = (s) => hex(crypto.createHash('sha256').update(s).digest()).slice(0, 32)
/** Nombre de archivo estable y corto para una pubkey (que es un JWK largo). */
export const writerFile = (pub) => hashOf(String(pub)) + '.jsonl'

/**
 * Abre el registro de este directorio.
 *
 * @param {string} dir
 * @param {object} o
 * @param {string} o.writer        pubkey de quien escribe (esta bóveda)
 * @param {(body:object)=>Promise<string>} o.sign     firma una entrada
 * @param {(a:{publickey:string,data:object,signature:string})=>Promise<boolean>} o.verify
 * @param {{encrypt:(t:string)=>string, decrypt:(t:string)=>string}} [o.atRest]
 *        Cifrado en reposo. Va POR LÍNEA y no por archivo: un archivo cifrado entero no se
 *        puede ir añadiendo, que es todo el punto de esto.
 */
export function openOpLog (dir, { writer, sign, verify, atRest = null } = {}) {
  if (!writer) throw new Error('oplog: missing writer')
  const logDir = path.join(dir, LOG_DIR)
  const mio = path.join(logDir, writerFile(writer))

  const cifra = (t) => (atRest ? atRest.encrypt(t) : t)
  const descifra = (t) => (atRest ? atRest.decrypt(t) : t)

  /** Las entradas de UN archivo, ya verificadas y encadenadas. Lo roto se descarta. */
  async function leerArchivo (f, puedeEscribir) {
    let texto
    try { texto = fs.readFileSync(f, 'utf8') } catch (_) { return { entradas: [], descartadas: 0 } }
    const entradas = []
    let descartadas = 0
    let prevHash = null
    for (const linea of texto.split('\n')) {
      if (!linea.trim()) continue
      let e
      try { e = JSON.parse(descifra(linea)) } catch (_) { descartadas++; continue }
      if (!e || typeof e.w !== 'string' || !Number.isInteger(e.n) || !Number.isInteger(e.l)) { descartadas++; continue }
      if (puedeEscribir && !puedeEscribir(e.w)) { descartadas++; continue }
      // LA CADENA. Cada entrada apunta al hash de la anterior DEL MISMO escritor, así que
      // quitar una del medio o reordenarlas rompe el enlace y se ve.
      if (e.prev !== prevHash) { descartadas++; continue }
      const { sig, ...cuerpo } = e
      if (!(await verify({ publickey: e.w, data: cuerpo, signature: sig }))) { descartadas++; continue }
      prevHash = hashOf(JSON.stringify(cuerpo))
      entradas.push(e)
    }
    return { entradas, descartadas }
  }

  return {
    dir: logDir,

    /** Los escritores que tienen registro aquí (por su archivo, no por el acta). */
    writers () {
      try { return fs.readdirSync(logDir).filter((n) => n.endsWith('.jsonl')) } catch (_) { return [] }
    },

    /**
     * Añade una operación al registro de ESTE escritor. Solo escribe en su archivo, así
     * que nunca compite con nadie — ni siquiera con otra bóveda sobre el mismo disco.
     *
     * `lamport` se pasa de fuera (lo sabe quien acaba de leer): mantener el reloj es del
     * llamante, y así este módulo no tiene estado que se quede viejo.
     */
    async append (op, { lamport = 1 } = {}) {
      fs.mkdirSync(logDir, { recursive: true, mode: 0o700 })
      const previas = await leerArchivo(mio, null)
      const ultima = previas.entradas[previas.entradas.length - 1] || null
      // El `prev` se calcula sobre el cuerpo SIN firma, exactamente igual que al leer: si
      // las dos formas no coinciden byte a byte, la cadena no valida y el registro entero
      // se descarta. Es el error más fácil de cometer aquí.
      const { sig: _firmaVieja, ...cuerpoUltima } = ultima || {}
      const cuerpo = {
        w: writer,
        n: (ultima?.n ?? 0) + 1,
        // El reloj no retrocede ni se queda quieto: al menos uno más que el mío anterior,
        // y al menos lo que haya visto de los demás.
        l: Math.max(lamport, (ultima?.l ?? 0) + 1),
        prev: ultima ? hashOf(JSON.stringify(cuerpoUltima)) : null,
        ts: Date.now(),
        op
      }
      const firma = await sign(cuerpo)
      const linea = cifra(JSON.stringify({ ...cuerpo, sig: firma }))
      fs.appendFileSync(mio, linea + '\n', { mode: 0o600 })
      return { n: cuerpo.n, l: cuerpo.l }
    },

    /**
     * TODAS las operaciones de TODOS los escritores, verificadas y en orden determinista.
     *
     * `puedeEscribir(pub)` sale del acta. Lo que venga de quien el acta no reconoce se
     * descarta — y se CUENTA, porque un registro que se ignora en silencio es la forma más
     * fácil de perder datos sin enterarse.
     */
    async replay ({ puedeEscribir = null } = {}) {
      let nombres = []
      try { nombres = fs.readdirSync(logDir).filter((n) => n.endsWith('.jsonl')) } catch (_) { return { ops: [], lamport: 0, descartadas: 0, escritores: 0 } }
      const todas = []
      let descartadas = 0
      for (const n of nombres) {
        const r = await leerArchivo(path.join(logDir, n), puedeEscribir)
        todas.push(...r.entradas)
        descartadas += r.descartadas
      }
      // EL ORDEN: Lamport, y a igual Lamport la pubkey menor. Determinista y sin relojes.
      todas.sort((a, b) => (a.l - b.l) || (a.w < b.w ? -1 : a.w > b.w ? 1 : a.n - b.n))
      return {
        ops: todas,
        lamport: todas.length ? todas[todas.length - 1].l : 0,
        descartadas,
        escritores: nombres.length
      }
    }
  }
}

/**
 * LA PROYECCIÓN: de las operaciones al JSON de siempre.
 *
 * Esta es la otra mitad de la idea. El archivo deja de ser la verdad y pasa a ser una
 * VISTA que se recalcula: la verdad es el registro. Así, dos bóvedas que escribieron cosas
 * distintas acaban con la misma vista sin que ninguna haya pisado a la otra.
 *
 * Semántica de cada operación, y son las mínimas que hacen falta para un `settings`:
 *   · `{ op:'set', k, v }`  fija una clave (gana la última en el orden, que es el mismo
 *                           para todos: eso es lo que lo vuelve determinista)
 *   · `{ op:'del', k }`     la borra
 *
 * Se deja `aplicar` para que cada almacén ponga las suyas: un árbol de contenido o unos
 * hilos no son un mapa de claves, y meter aquí sus reglas convertiría esto en un cajón de
 * sastre. Lo que este módulo garantiza es el ORDEN; qué significa cada operación es del
 * almacén que la escribió.
 */
export function project (ops, { aplicar = null, inicial = {} } = {}) {
  const estado = { ...inicial }
  for (const e of ops) {
    const op = e?.op
    if (!op || typeof op !== 'object') continue
    if (aplicar && aplicar(estado, op, e) === true) continue   // el almacén la entendió
    if (op.op === 'set' && typeof op.k === 'string') estado[op.k] = op.v
    else if (op.op === 'del' && typeof op.k === 'string') delete estado[op.k]
  }
  return estado
}

export default { openOpLog, project, writerFile, LOG_DIR }
