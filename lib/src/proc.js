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
import { cleanMachine } from '@dotrino/identity/machine'
import { MAX_PATH_BYTES, clip, trimArgv, sanitizeContext, commandFingerprint, sameCommand, commandLine } from './procContext.js'

export { MAX_ARGV_BYTES, MAX_PATH_BYTES, MAX_ARGV_ITEMS, sanitizeContext, commandFingerprint, sameCommand, commandLine } from './procContext.js'

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
  const measured = readProcContext(process.pid)
  if (measured) return { ...measured, user: userName(), host: os.hostname() }
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

/**
 * DÓNDE CORRE ESTE PROCESO (`@dotrino/identity/machine`): para que la bóveda lo reconozca en
 * su lista de aparatos. Va en lo que el aparato firma al emparejarse y en cada pedido de
 * secretos, así que se refresca solo cuando cambia de máquina o de sistema.
 */
export function selfMachine () {
  const kind = os.type()
  const system = kind === 'Darwin' ? 'macOS' : kind === 'Windows_NT' ? 'Windows' : kind
  return cleanMachine({ kind: 'node', os: `${system} ${os.release()}`, name: os.hostname() })
}

const safeCwd = () => { try { return process.cwd() } catch (_) { return '' } }
const userName = () => { try { return os.userInfo().username } catch (_) { return '' } }

export default { selfContext, readProcContext, sanitizeContext, commandFingerprint, sameCommand, commandLine, hasProc }
