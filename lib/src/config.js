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
 * Config por entorno:
 *   DOTRINO_NS            namespace de secretos (si no, el único enrolado en la máquina)
 *   DOTRINO_ENV_DIR       directorio de la identidad del servicio (si no, ~/.dotrino/service/<ns>)
 *   DOTRINO_ENV_QUIET     '1' para no imprimir la línea de arranque
 *   DOTRINO_ENV_OVERRIDE  '0' para NO pisar el entorno en esta corrida (depuración)
 */
import { loadEnv } from './env.js'

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
