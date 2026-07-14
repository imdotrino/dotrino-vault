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
 * Config por entorno:
 *   DOTRINO_NS         namespace de secretos (si no, el único enrolado en la máquina)
 *   DOTRINO_ENV_DIR    directorio de la identidad del servicio (si no, ~/.dotrino/service/<ns>)
 *   DOTRINO_ENV_QUIET  '1' para no imprimir la línea de arranque
 */
import { loadEnv } from './env.js'

const quiet = process.env.DOTRINO_ENV_QUIET === '1'

const { ns, injected } = await loadEnv({
  onRetry: (e, ms) => {
    if (!quiet) console.error('[dotrino-env] vault no disponible (%s); reintentando en %ds…', e.message, Math.round(ms / 1000))
  }
})

if (!quiet) console.error('[dotrino-env] %d secreto(s) del ns "%s" cargados en process.env', injected.length, ns)
