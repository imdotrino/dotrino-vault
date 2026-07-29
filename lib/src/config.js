/**
 * `import '@dotrino/vault/config'` — el equivalente de `import 'dotenv/config'`,
 * pero contra el vault del dueño.
 *
 * Bloquea el arranque (top-level await) hasta que los secretos del ns estén en
 * `process.env`. Si el vault no está disponible, ESPERA (reintento con backoff):
 * la regla del ecosistema es que un servicio sin vault no arranca — no opera con
 * secretos viejos ni vacíos. Un fallo NO transitorio (sin enrolar, cert revocado,
 * scope equivocado) sí aborta el proceso.
 *
 * EL VAULT MANDA: lo que venga de aquí PISA lo que ya hubiera en el entorno
 * (incluido un `.env` cargado antes). Ver `env.js` para el porqué.
 *
 * Y queda A LA ESCUCHA: cuando el dueño cambia la configuración en la bóveda, el
 * proceso TERMINA para que su supervisor lo levante limpio. No se recarga en
 * caliente a propósito — salir borra de la memoria el valor viejo, que en
 * JavaScript no hay forma de borrar de otra manera, y una llave se rota casi
 * siempre porque se filtró. Requiere correr bajo pm2 o systemd `Restart=always`.
 * Se apaga con `DOTRINO_ENV_WATCH=0`.
 *
 * Config por entorno:
 *   DOTRINO_NS            namespace de secretos (si no, el único enrolado en la máquina)
 *   DOTRINO_ENV_DIR       directorio de la identidad del servicio (si no, ~/.dotrino/service/<ns>)
 *   DOTRINO_ENV_QUIET     '1' para no imprimir la línea de arranque
 *   DOTRINO_ENV_OVERRIDE  '0' para NO pisar el entorno en esta corrida (depuración)
 *   DOTRINO_ENV_WATCH     '0' para no escuchar avisos de cambio (no terminar solo)
 */
import { loadEnv, watchEnv } from './env.js'

const quiet = process.env.DOTRINO_ENV_QUIET === '1'

const { ns, injected, overridden } = await loadEnv({
  onRetry: (e, ms) => {
    if (!quiet) console.error('[dotrino-env] vault no disponible (%s); reintentando en %ds…', e.message, Math.round(ms / 1000))
  }
})

if (!quiet) {
  console.error('[dotrino-env] %d valor(es) del ns "%s" cargados en process.env', injected.length, ns)
  // Se dice en voz alta: que el vault haya tenido que pisar algo significa que
  // en esta máquina hay un `.env` con valores viejos. Ganó el vault, pero el
  // operador quiere enterarse — es la señal de que quedó basura por limpiar.
  if (overridden.length) {
    console.error('[dotrino-env] pisaron un valor previo del entorno: %s', overridden.join(', '))
  }
}

// La escucha no debe impedir que el proceso termine por su cuenta si no tiene
// nada más que hacer, así que si falla (agente sin enrolar del todo, proxio
// caído) se avisa y se sigue: el servicio ya tiene su configuración; lo único
// que pierde es enterarse del próximo cambio.
if (process.env.DOTRINO_ENV_WATCH !== '0') {
  try {
    await watchEnv({ ns, quiet })
  } catch (e) {
    if (!quiet) console.error('[dotrino-env] sin escucha de cambios (%s): habrá que reiniciar a mano al rotar', e.message)
  }
}
