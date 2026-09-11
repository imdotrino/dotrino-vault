/**
 * proc.js — QUIÉN ESTÁ PIDIENDO LOS SECRETOS: qué comando, desde qué carpeta.
 *
 * Hasta ahora un pedido de aprobación decía «el aparato 904C-1002 pide el cajón proxy» y
 * nada más. Con eso no se puede decidir: el dueño no sabe si es el arranque que acaba de
 * lanzar o cualquier otra cosa de la misma máquina. Lo que hace falta es el **comando** y
 * el **path** (dueño, 2026-09-11).
 *
 * DOS FUENTES, Y NO VALEN LO MISMO:
 *
 *   · `selfContext()` — lo que un proceso dice de sí mismo. Es lo que viaja en el pedido.
 *   · `readProcContext(pid)` — lo que el KERNEL dice de ese pid, leyendo `/proc`. Solo la
 *     puede usar quien está en la misma máquina, y es la que manda.
 *
 * Cuando el pedido entra por el mostrador local, la bóveda lee la segunda y la compara con
 * la primera: si no cuadran, no es un matiz, es una mentira, y se deniega. Cuando entra por
 * el proxio (un servicio en otra máquina) no hay nada que leer, y entonces lo declarado se
 * marca como declarado — que es distinto de comprobado, y se enseña distinto.
 *
 * EL LÍMITE, DICHO EN VOZ ALTA: esto no es una credencial. Cualquier proceso del MISMO
 * usuario puede leer `service-identity.json` y pedir los secretos con esa llave, y también
 * puede llamarse como quiera (`exec -a`) y arrancar desde donde quiera. La frontera de
 * verdad es el usuario, no el proceso. Esto existe para que quien aprueba decida con lo que
 * está pasando delante, y para que quede rastro — no para parar a quien ya tiene la llave.
 *
 * En `dotrino-env run -- node server.js` el comando de destino ya va DENTRO de la línea de
 * comandos del propio `dotrino-env`, así que se mide igual que todo lo demás: no hay que
 * creerle nada aparte.
 */
import fs from 'node:fs'
import os from 'node:os'
import crypto from 'node:crypto'

/** Topes. Un `argv` puede ser enorme y esto viaja en cada pedido y se pinta en un teléfono. */
export const MAX_ARGV_BYTES = 4096
export const MAX_PATH_BYTES = 1024
/** Cuántos argumentos como mucho: más que esto no lo lee nadie. */
export const MAX_ARGV_ITEMS = 64

const clip = (s, max) => {
  if (typeof s !== 'string') return ''
  return Buffer.byteLength(s) <= max ? s : Buffer.from(s).subarray(0, max).toString('utf8')
}

/** ¿Hay `/proc`? Es lo que separa poder medir de tener que creer. */
export const hasProc = () => { try { return fs.statSync('/proc/self').isDirectory() } catch (_) { return false } }

/** `/proc/<pid>/cmdline` viene separado por NUL y termina en NUL. */
function readCmdline (pid) {
  const raw = fs.readFileSync(`/proc/${pid}/cmdline`, 'utf8')
  const parts = raw.split('\0')
  if (parts.length && parts[parts.length - 1] === '') parts.pop()
  return parts
}

/**
 * Recorta el `argv` a lo que se puede enseñar y transportar. Devuelve también si sobró
 * algo: un comando cortado que no dice que está cortado se lee como otro comando.
 */
function trimArgv (argv) {
  const list = (Array.isArray(argv) ? argv : []).map((a) => String(a))
  let cut = list.length > MAX_ARGV_ITEMS
  const kept = list.slice(0, MAX_ARGV_ITEMS)
  let total = 0
  const out = []
  for (const a of kept) {
    const b = Buffer.byteLength(a)
    if (total + b > MAX_ARGV_BYTES) { cut = true; break }
    total += b
    out.push(a)
  }
  return { argv: out, truncated: cut }
}

/**
 * LA HORA DE ARRANQUE del proceso (campo 22 de `/proc/<pid>/stat`, en ticks). Sirve para
 * saber que el pid no se recicló entre que pidió y que se miró: el nombre del proceso va
 * entre paréntesis y puede llevar espacios, así que se corta por el ÚLTIMO `)`.
 */
function readStart (pid) {
  try {
    const stat = fs.readFileSync(`/proc/${pid}/stat`, 'utf8')
    const campos = stat.slice(stat.lastIndexOf(')') + 2).split(' ')
    const t = Number(campos[19])
    return Number.isFinite(t) ? t : null
  } catch (_) { return null }
}

/**
 * Lo que el KERNEL dice del proceso `pid`. `null` si no hay `/proc`, si el proceso ya no
 * está o si no se puede mirar (otro usuario). No se inventa nada: no poder medir se
 * contesta como no poder medir.
 */
export function readProcContext (pid) {
  if (!hasProc() || !Number.isInteger(pid) || pid <= 0) return null
  try {
    const st = fs.statSync(`/proc/${pid}`)
    const { argv, truncated } = trimArgv(readCmdline(pid))
    return {
      pid,
      uid: st.uid,
      exe: clip(fs.readlinkSync(`/proc/${pid}/exe`), MAX_PATH_BYTES),
      cwd: clip(fs.readlinkSync(`/proc/${pid}/cwd`), MAX_PATH_BYTES),
      argv,
      truncated,
      start: readStart(pid)
    }
  } catch (_) { return null }
}

/**
 * Lo que ESTE proceso dice de sí mismo. En Linux sale de `/proc/self`, o sea de la misma
 * fuente que va a leer la bóveda: así lo declarado y lo medido coinciden byte a byte y una
 * diferencia significa lo que tiene que significar. Fuera de Linux se arma con lo que da
 * Node, y entonces no hay nada que comprobar al otro lado.
 */
export function selfContext () {
  const medido = readProcContext(process.pid)
  if (medido) return { ...medido, user: userName(), host: os.hostname() }
  const { argv, truncated } = trimArgv([process.execPath, ...process.argv.slice(1)])
  return {
    pid: process.pid,
    uid: typeof process.getuid === 'function' ? process.getuid() : null,
    exe: clip(process.execPath, MAX_PATH_BYTES),
    cwd: clip(safeCwd(), MAX_PATH_BYTES),
    argv,
    truncated,
    start: null,
    user: userName(),
    host: os.hostname()
  }
}

const safeCwd = () => { try { return process.cwd() } catch (_) { return '' } }
const userName = () => { try { return os.userInfo().username } catch (_) { return '' } }

/**
 * LO QUE LLEGA POR LA RED NO SE CREE NI EN LA FORMA. Este dato lo manda otro proceso, se
 * guarda en memoria y se pinta en un teléfono: se recorta a lo que cabe y se tira lo que no
 * tiene el tipo que debería. Devuelve `null` si no queda nada que enseñar — que no es lo
 * mismo que un contexto vacío, y por eso no se devuelve un objeto a medias.
 */
export function sanitizeContext (raw) {
  if (!raw || typeof raw !== 'object') return null
  const argvRaw = Array.isArray(raw.argv) ? raw.argv.filter((a) => typeof a === 'string') : []
  const { argv, truncated } = trimArgv(argvRaw)
  const exe = clip(typeof raw.exe === 'string' ? raw.exe : '', MAX_PATH_BYTES)
  const cwd = clip(typeof raw.cwd === 'string' ? raw.cwd : '', MAX_PATH_BYTES)
  if (!exe && !argv.length) return null
  return {
    pid: Number.isInteger(raw.pid) && raw.pid > 0 ? raw.pid : null,
    uid: Number.isInteger(raw.uid) ? raw.uid : null,
    exe,
    cwd,
    argv,
    truncated: truncated || raw.truncated === true,
    start: Number.isFinite(raw.start) ? raw.start : null,
    user: clip(typeof raw.user === 'string' ? raw.user : '', 64),
    host: clip(typeof raw.host === 'string' ? raw.host : '', 64)
  }
}

/**
 * LA HUELLA DEL COMANDO: qué binario, desde qué carpeta y con qué argumentos. Es la llave
 * de la concesión por tiempo — aprobar `node server.js` en `/srv/app` no aprueba otra cosa
 * ni la misma cosa en otro sitio.
 *
 * El pid NO entra: cambia en cada arranque y la gracia es justamente que el mismo comando
 * se reconozca la próxima vez.
 */
export function commandFingerprint (ctx) {
  if (!ctx || typeof ctx !== 'object') return null
  const argv = Array.isArray(ctx.argv) ? ctx.argv : []
  if (!ctx.exe && !argv.length) return null
  const material = [ctx.exe || '', ctx.cwd || '', ...argv].join('\0')
  return crypto.createHash('sha256').update(material).digest('hex')
}

/** ¿Son el mismo comando? Mismo binario, misma carpeta, mismos argumentos. */
export const sameCommand = (a, b) => {
  const fa = commandFingerprint(a)
  return !!fa && fa === commandFingerprint(b)
}

/** El comando en una línea, para un log o una pantalla estrecha. */
export function commandLine (ctx, max = 160) {
  const argv = Array.isArray(ctx?.argv) ? ctx.argv : []
  const linea = argv.length ? argv.join(' ') : (ctx?.exe || '')
  return linea.length > max ? linea.slice(0, max - 1) + '…' : linea
}

export default { selfContext, readProcContext, sanitizeContext, commandFingerprint, sameCommand, commandLine, hasProc }
