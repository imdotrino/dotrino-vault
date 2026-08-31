/**
 * selfupdate.js — ACTUALIZAR EL PAQUETE TENÍA QUE SIGNIFICAR ACTUALIZAR EL SERVICIO.
 *
 * No lo significaba, y el resultado era una bóveda que decía correr una versión y corría
 * otra. Pasó de verdad (dueño, 2026-08-31): el `.deb` puso 0.56.0 en el disco y el daemon
 * siguió ocho versiones atrás durante días, sin que nada fallara de forma visible —
 * `status` lo avisaba en una línea que nadie mira, y el aviso del instalador se pierde
 * entre el resto de la salida.
 *
 * POR QUÉ EL INSTALADOR NO PUEDE HACERLO. La unidad es de USUARIO (`systemctl --user`) y
 * el `postinst` del paquete corre como root. Root no tiene la sesión del usuario: para
 * reiniciarle el servicio tendría que averiguar qué usuarios lo tienen puesto, buscar su
 * `XDG_RUNTIME_DIR` y entrar en su bus. Es frágil, y con varios usuarios en la máquina es
 * además decidir por ellos. Por eso el instalador solo lo dice.
 *
 * ASÍ QUE LO HACE EL DAEMON. Mira su propio binario y, cuando cambia, se va limpiamente;
 * systemd lo levanta otra vez (`Restart=always`) y esa vez arranca el nuevo. Es la única
 * vía que no necesita root, funciona con cualquier número de usuarios y no depende de que
 * nadie se acuerde de nada.
 *
 * LAS DOS CONDICIONES, y ninguna es opcional:
 *
 *   1. **Que haya quien nos levante.** Si nadie nos reinicia, irse es apagar la bóveda del
 *      usuario para siempre — el peor final posible para una mejora de comodidad. Se exige
 *      `INVOCATION_ID`, que systemd pone en el entorno del servicio: sin eso, no se toca
 *      nada. Un `npx`, un contenedor o un arranque a mano quedan fuera a propósito.
 *   2. **Que el archivo esté quieto.** Un `.deb` a medio escribir cambia de tamaño varias
 *      veces; irse en ese instante deja a systemd arrancando un binario truncado. Por eso
 *      la huella nueva tiene que verse en DOS pasadas seguidas: si aún se está copiando,
 *      la segunda no coincide y se vuelve a esperar.
 */
import fs from 'node:fs'
import path from 'node:path'

/**
 * Cada cuánto se mira. No hay prisa: un minuto de retraso en actualizar no le duele a
 * nadie, y este mismo plazo hace de espera — la huella nueva tiene que verse DOS veces
 * seguidas, así que un archivo a medio escribir no llega a contar.
 */
export const CHECK_MS = 60_000

/** Huella barata del archivo: tamaño + fecha. No hace falta leerlo entero (son 125 MB). */
function fingerprint (file) {
  try { const s = fs.statSync(file); return `${s.size}:${Math.round(s.mtimeMs)}` } catch (_) { return null }
}

/**
 * ¿Estamos corriendo el binario autosuficiente, bajo un systemd que nos va a levantar?
 *
 * `process.execPath` es el binario cuando es un SEA, y es `node` cuando se corre desde el
 * repo o por npx. En ese segundo caso vigilar no tiene sentido: actualizar el paquete no
 * cambia `node`, y lo que habría que mirar es otra cosa.
 */
export function shouldWatch (env = process.env, execPath = process.execPath) {
  if (!env.INVOCATION_ID) return false                    // nadie garantiza el reinicio
  return /dotrino-vaultd/.test(path.basename(execPath))   // el binario, no `node`
}

/**
 * Vigila el binario propio y termina el proceso cuando cambie.
 * @returns {{stop:()=>void}|null} `null` si no procede vigilar.
 */
export function watchBinary ({ log = console.log, exit = (c) => process.exit(c), env = process.env, execPath = process.execPath, checkMs = CHECK_MS } = {}) {
  if (!shouldWatch(env, execPath)) return null
  const inicial = fingerprint(execPath)
  if (!inicial) return null

  let quieto = null // huella del candidato, para exigir que se repita

  const t = setInterval(() => {
    const ahora = fingerprint(execPath)
    if (!ahora || ahora === inicial) { quieto = null; return }
    if (quieto !== ahora) { quieto = ahora; return } // primera vez que se ve: esperar
    clearInterval(t)
    log('[vault] the binary changed on disk: restarting to run the new version')
    // Se sale con 0 y limpiamente: systemd lo trata como una parada normal y vuelve a
    // arrancar por `Restart=always`. El apagado del daemon ya suelta el candado y cierra
    // el transporte, así que la bóveda no queda ni con el candado puesto ni a medias.
    exit(0)
  }, Math.max(1000, checkMs))
  t.unref?.()

  return { stop: () => clearInterval(t) }
}

export default { watchBinary, shouldWatch, CHECK_MS }
