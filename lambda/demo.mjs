/**
 * LA DEMO (`Mode: demo`): la bóveda y, en el mismo proceso, el agente de Dotrino Terminal.
 *
 * Es para quien revisa una app en una tienda (dueño, 2026-10-23): entra con usuario y
 * contraseña, eso despierta la Lambda, y la máquina «demo» aparece en Terminal mientras dure la
 * sesión. Sirve también de prueba del login contra una bóveda en Lambda.
 *
 * Lo que tiene de distinto respecto de `vault`:
 *
 *   · El agente vive en `<perfil>/terminal-agent/`, que se refleja en el almacén con lo demás:
 *     su enlace (`link.json`) sobrevive al frío. La primera sesión lo enrola con una invitación
 *     de ESTA bóveda y aprueba su código ella misma: invitación + código, como cualquier alta.
 *   · Una consola abierta y usada hace poco cuenta como trabajo: la sesión no se apaga mientras
 *     alguien escribe. El tope sigue siendo el de la función (15 min).
 *   · SIN TERMINAL: Lambda no tiene pseudoterminales (`/dev/ptmx` no existe). Donde falta, el
 *     `node-pty` del agente se sustituye por `pipe-pty.mjs` (tuberías + eco de líneas): se
 *     teclean órdenes y se ve la salida, pero no hay programas de pantalla completa.
 *   · La shell arranca con el entorno VACÍO (`demo-shell.sh`): sin las credenciales de la
 *     función. No es un aislamiento —mismo usuario que la bóveda, y `/proc` deja leer el entorno
 *     del proceso padre—; la cuenta demo es desechable y el rol solo alcanza su bucket y su llave.
 */
import fs from 'node:fs'
import path from 'node:path'
import { createRequire, Module } from 'node:module'
import { vaultStarter } from './session.mjs'
import pipePty from './pipe-pty.mjs'

/** Sin mensajes ni consolas en uso durante esto, la demo se apaga. Más que `IDLE_MS`: el revisor lee. */
export const DEMO_IDLE_MS = 5 * 60_000
/** Una consola sin teclear durante esto ya no sostiene la sesión. */
export const CONSOLE_IDLE_MS = 5 * 60_000
/** Lo que se espera a que el agente se enrole en la primera sesión. */
const ENROLL_WAIT_MS = 60_000
/** El nombre del agente en el acta y en la lista de Terminal. */
export const AGENT_LABEL = 'terminal-agent'

const shell = () => path.join(process.env.LAMBDA_TASK_ROOT || '/var/task', 'lambda', 'demo-shell.sh')

/**
 * Sin `/dev/ptmx`, el `node-pty` que carga el agente (`loadPty`, con `require`) pasa a ser
 * `pipe-pty.mjs`: se deja en la caché de módulos con la ruta que el agente va a pedir. Con
 * terminal no se toca nada.
 *
 * @param {string} agentEntry  la ruta del paquete del agente (de ahí se resuelve su `node-pty`)
 * @returns {boolean} si se sustituyó
 */
export function pipePtyWhenNoTerminal (agentEntry) {
  if (fs.existsSync('/dev/ptmx')) return false
  const file = createRequire(agentEntry).resolve('node-pty')
  const m = new Module(file)
  m.filename = file
  m.loaded = true
  m.exports = pipePty
  Module._cache[file] = m
  return true
}

/**
 * Enrola el agente con una invitación de esta bóveda y aprueba su código aquí mismo. Sin agente
 * enrolado la demo no sirve para nada: si no sale, se para y se dice.
 */
async function enrollAgent (vault, { agentDir, enroll, log }) {
  // Los mismos permisos que da `dotrino-vault pair` por defecto: el agente renueva su papel
  // exigiendo `vault:sign`, y con menos lo rechazaría en cada renovación.
  const { qr } = await vault.startPairing({ scope: ['vault:sign', 'vault:read', 'vault:store'], label: AGENT_LABEL, ttlMs: ENROLL_WAIT_MS })
  let timer = null
  const timeout = new Promise((_, reject) => {
    timer = setTimeout(() => reject(Object.assign(new Error('the demo agent did not enroll in time'), { code: 'agent-enroll-timeout' })), ENROLL_WAIT_MS)
  })
  try {
    await Promise.race([timeout, enroll({
      qr,
      dir: agentDir,
      label: AGENT_LABEL,
      onChallenge: ({ deviceId, code }) => {
        log(`[vault-lambda] demo agent ${deviceId}: approving its code`)
        vault.approveDevice(code).catch((e) => log(`[vault-lambda] could not approve the demo agent: ${e.code || ''} ${e.message}`))
      }
    })])
  } finally { clearTimeout(timer) }
  log('[vault-lambda] demo agent enrolled')
}

/**
 * Como `vaultStarter`, más el agente. `startAgent` y `enroll` vienen de `@dotrino/terminal-agent`
 * y `@dotrino/remote-agent/link`, que solo están en el zip de la demo (`build.sh --demo`).
 */
export const demoStarter = ({ startVault, startAgent, enroll, loadLink, onReady = null }) => async (args) => {
  const { dir, log } = args
  const agentDir = path.join(dir, AGENT_LABEL)
  let agent = null
  const base = await vaultStarter({
    startVault,
    onReady: async (vault) => {
      fs.mkdirSync(agentDir, { recursive: true })
      if (!loadLink(agentDir)) await enrollAgent(vault, { agentDir, enroll, log })
      agent = await startAgent({ dir: agentDir, shell: shell(), quiet: false })
      // Lo que el agente cambie (el acta que renueva) va al almacén con lo de la bóveda.
      await args.push()
      return onReady ? onReady(vault) : null
    }
  })(args)
  const inUse = () => {
    const now = Date.now()
    for (const c of agent?.consoles?.consoles?.values() || []) if (now - (c.lastActive || 0) < CONSOLE_IDLE_MS) return true
    return false
  }
  return {
    ready: base.ready,
    busy: () => base.busy() || inUse(),
    close: () => { try { agent?.close() } finally { base.close() } }
  }
}

export default { demoStarter, DEMO_IDLE_MS, CONSOLE_IDLE_MS, AGENT_LABEL }
