/**
 * update.js — lo que es DEL VAULT al actualizarse, y nada más.
 *
 * La mecánica —comparar versiones, preguntar a GitHub, bajar y verificar contra sigstore—
 * vive en `@dotrino/update`, porque es la misma para el proxio, geo, los agentes y los
 * comandos (CONVENCIONES §15). Aquí solo queda lo que sabe el vault de sí mismo: en qué
 * repo sale y cómo se llaman sus archivos.
 *
 * Antes de existir el paquete esto era una copia entera de esa mecánica. Dos copias de lo
 * mismo son dos sitios donde arreglar el mismo fallo, y el segundo siempre se olvida.
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync, spawn } from 'node:child_process'
import { latestVersion, isNewer, CHECK_EVERY_MS } from '@dotrino/update'
import { pickAsset, download, verifyArtifact as verify, fetchVerified } from '@dotrino/update/fetch'
import { VERSION } from './version.js'
import { ipcWrite } from './ipc.js'

export const REPO = 'imdotrino/dotrino-vault'
export { isNewer, CHECK_EVERY_MS, download }

/** La última release del vault. `{ ok:false, reason }` si no se pudo mirar, que NO es «al día». */
/**
 * DEJA DICHO QUE SE INSTALÓ una versión nueva, para que el servicio se lo cuente a quien
 * aprueba cuando arranque con ella (`anunciarActualizacion` en daemon.js). Es el mismo
 * marcador que deja el servicio cuando se actualiza solo, y lo dejan igual el comando
 * `update` y la TUI.
 */
export function noteUpdated (dir, { from, to }) {
  ipcWrite(path.join(dir, 'updated.json'), { v: 1, from, to, at: Date.now() })
}

export const latestRelease = (opts = {}) =>
  latestVersion({ source: 'github', repo: REPO, product: 'dotrino-vault', version: VERSION, ...opts })

/**
 * Con qué instala paquetes esta máquina: `'deb'`, `'rpm'` o `null` (ninguno de los dos).
 * `dpkg` va primero: en Debian y Ubuntu es normal tener además la herramienta `rpm`
 * instalada (para empaquetar), y ahí lo que instala sigue siendo `dpkg`.
 */
export function systemPackager (exists = fs.existsSync) {
  if (exists('/usr/bin/dpkg')) return 'deb'
  if (exists('/usr/bin/rpm')) return 'rpm'
  return null
}

/**
 * Qué archivo le toca a esta máquina. El `.deb` donde se instala con `dpkg`, el `.rpm`
 * donde se instala con `rpm` (Fedora, RHEL, openSUSE); en cualquier otro Linux, el tarball.
 * Fuera de Linux no se emite binario, y se dice en vez de bajar algo inútil.
 */
export function assetFor (assets, { platform = process.platform, arch = process.arch, packager = undefined } = {}) {
  if (platform !== 'linux') return { ok: false, reason: `there is no binary for ${platform}: update with npm (npx @dotrino/vaultd)` }
  if (arch !== 'x64') return { ok: false, reason: `there is no binary for ${arch}` }
  const pk = packager === undefined ? systemPackager() : packager
  return pickAsset(assets, [
    { kind: 'deb', re: /_amd64\.deb$/, when: () => pk === 'deb' },
    { kind: 'rpm', re: /\.x86_64\.rpm$/, when: () => pk === 'rpm' },
    { kind: 'tar', re: /-linux-x64\.tar\.gz$/ }
  ])
}

/** Verifica contra la atestación del release del vault. Sin `gh`, no se instala. */
export const verifyArtifact = (file, opts = {}) => verify(file, { repo: REPO, ...opts })


/**
 * INSTALACIÓN DE USUARIO: los binarios viven en `~/.local/share/dotrino/bin`, que es del
 * usuario, y la bóveda se actualiza sin `sudo` (dueño, 2026-09-24).
 *
 * Es esa carpeta y no `~/.local/bin` por una razón concreta: la unidad de systemd lleva
 * `ProtectHome=read-only` y solo deja escribir en `~/.local/share/dotrino`. Desde ahí el
 * daemon puede reemplazar su propio binario; en `~/.local/bin` no podría.
 *
 * El precio, dicho: un proceso de ese mismo usuario también podría reemplazarlo, cosa que
 * con el `.deb` en `/usr/bin` (de root) no. En el modelo de la bóveda la frontera ya es el
 * usuario (memoria `dotrino-aprobacion-comando`), y el binario nuevo solo entra verificado.
 */
export function userBinDir (home = os.homedir()) {
  return path.join(home, '.local', 'share', 'dotrino', 'bin')
}

/** ¿Corre este proceso desde la instalación de usuario? Solo entonces puede actualizarse solo. */
export function isUserInstall (execPath = process.execPath, home = os.homedir()) {
  return path.dirname(execPath) === userBinDir(home)
}

/**
 * Baja el tarball del release, lo VERIFICA contra su atestación y cambia los dos binarios
 * de forma atómica (se escribe al lado y se renombra encima: nunca queda uno a medias).
 * `selfupdate.js` ve el binario nuevo y el servicio se reinicia solo.
 *
 * Si la verificación falla no se toca nada, y se devuelve por qué.
 *
 * @returns {Promise<{ok:true, version:string} | {ok:false, code?:string, reason:string, file?:string}>}
 */
export async function installUserRelease (release, { binDir = userBinDir(), log = () => {}, fetchVerifiedImpl = fetchVerified } = {}) {
  const pick = pickAsset(release.assets, [{ kind: 'tar', re: /-linux-x64\.tar\.gz$/ }])
  if (!pick.ok) return pick
  // SE TRABAJA EN DISCO, al lado de los binarios, y no en /tmp: en un VPS /tmp es un tmpfs
  // (memoria) de unos cientos de MB, y el tarball (41 MB) más el binario (125 MB) no cabían
  // — tar falló con «Disk quota exceeded» en la bóveda de Dotrino (2026-09-24). Además es la
  // única carpeta que la unidad deja escribir. La carpeta se borra al acabar, salga como salga.
  const work = path.join(path.dirname(binDir), 'update')
  fs.rmSync(work, { recursive: true, force: true })
  fs.mkdirSync(work, { recursive: true, mode: 0o700 })
  try {
    return await installFrom(work, pick, release, { binDir, log, fetchVerifiedImpl })
  } finally {
    try { fs.rmSync(work, { recursive: true, force: true }) } catch (_) {}
  }
}

async function installFrom (work, pick, release, { binDir, log, fetchVerifiedImpl }) {
  const got = await fetchVerifiedImpl(pick.asset, { repo: REPO, product: 'dotrino-vault', version: VERSION, dir: work })
  if (!got.ok) return got
  log(`[vault] update: ${pick.asset.name} verified against its attestation`)
  try { execFileSync('tar', ['xzf', got.file, '-C', work], { stdio: ['ignore', 'ignore', 'pipe'] }) } catch (e) {
    // El motivo de tar es lo que sirve («Disk quota exceeded», …): se dice, no solo «falló».
    return { ok: false, code: 'UNPACK_FAILED', reason: `could not unpack the release: ${String(e.stderr || e.message).trim().split('\n').slice(-2).join(' · ')}` }
  }
  const src = fs.readdirSync(work).map((d) => path.join(work, d)).find((d) => fs.existsSync(path.join(d, 'dotrino-vaultd')))
  if (!src) return { ok: false, code: 'BAD_TARBALL', reason: 'the tarball has no dotrino-vaultd inside' }
  fs.mkdirSync(binDir, { recursive: true })
  // LA VENTANA se pone al día con la bóveda, pero solo donde ya estaba: una bóveda de
  // servidor no tiene por qué recibir un programa de escritorio que nadie instaló.
  const names = ['dotrino-vault', 'dotrino-vaultd']
  if (fs.existsSync(path.join(binDir, 'dotrino-vault-desktop')) && fs.existsSync(path.join(src, 'dotrino-vault-desktop'))) names.unshift('dotrino-vault-desktop')
  // El CLI primero y el daemon al final: cambiar el daemon es lo que dispara el reinicio.
  for (const name of names) {
    const tmp = path.join(binDir, `.${name}.new`)
    fs.copyFileSync(path.join(src, name), tmp)
    fs.chmodSync(tmp, 0o755)
    fs.renameSync(tmp, path.join(binDir, name))
  }
  return { ok: true, version: release.version }
}

// ------------------------- Windows y macOS ---------------------------------

/**
 * CÓMO ESTÁ INSTALADO ESTE BINARIO, y por tanto si puede actualizarse solo (CONVENCIONES §15).
 *
 *   'user'    Linux, instalación de usuario (`~/.local/share/dotrino/bin`): cambia sus binarios.
 *   'inno'    Windows, el instalador por usuario (`unins000.exe` al lado): corre el instalador
 *             nuevo en silencio, que cierra la bóveda, la reemplaza y la vuelve a arrancar.
 *   'app'     macOS, dentro de `Dotrino Vault.app` en una carpeta que se puede escribir: se
 *             cambia la app entera (nunca un binario suelto: la app es un conjunto firmado).
 *   'system'  un paquete de root (.deb/.rpm), o una app en una carpeta que no es tuya.
 *   'other'   npm, Docker, un checkout: se actualiza por su propia vía.
 */
export function installKind ({ platform = process.platform, execPath = process.execPath, home = os.homedir(), exists = fs.existsSync, writable = canWrite } = {}) {
  const sea = /^dotrino-vaultd(\.exe)?$/.test(path.basename(execPath))
  if (!sea) return 'other'
  if (platform === 'linux') return isUserInstall(execPath, home) ? 'user' : execPath.startsWith('/usr/') ? 'system' : 'other'
  if (platform === 'win32') return exists(path.join(path.dirname(execPath), 'unins000.exe')) ? 'inno' : 'other'
  if (platform === 'darwin') {
    const app = appBundleOf(execPath)
    if (!app) return 'other'
    return writable(path.dirname(app)) ? 'app' : 'system'
  }
  return 'other'
}

/** ¿Puede este binario instalar él mismo la versión nueva? */
export const canSelfUpdate = (opts) => ['user', 'inno', 'app'].includes(installKind(opts))

/** `/Applications/Dotrino Vault.app` a partir de su `Contents/MacOS/dotrino-vaultd`. */
export function appBundleOf (execPath) {
  const m = /^(.*\.app)\/Contents\/MacOS\/dotrino-vaultd$/.exec(execPath)
  return m ? m[1] : null
}

function canWrite (dir) { try { fs.accessSync(dir, fs.constants.W_OK); return true } catch { return false } }

/** Carpeta de trabajo de las descargas: la de los datos de Dotrino del usuario, no `/tmp`. */
function updateWorkDir (platform = process.platform) {
  if (platform === 'win32') return path.join(process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local'), 'Dotrino', 'update')
  return path.join(os.homedir(), '.local', 'share', 'dotrino', 'update')
}

/**
 * INSTALA la versión nueva por la vía de este sistema. Lo que se baja se verifica contra la
 * atestación del release antes de tocar nada; si no cuadra, no se toca nada y se dice.
 *
 * `then` dice qué tiene que hacer quien llamó:
 *   'watch'  Linux: el binario cambió en su sitio; el vigilante (o systemd) lo reinicia.
 *   'exit'   el proceso que corre la bóveda tiene que irse YA. En Windows el instalador lo
 *            cierra y lo vuelve a arrancar; en macOS lo levanta launchd o el relanzador.
 *
 * @returns {Promise<{ok:true, version:string, then:'watch'|'exit'} | {ok:false, code?:string, reason:string, file?:string}>}
 */
export async function installRelease (release, { log = () => {}, kind = installKind(), fetchVerifiedImpl = fetchVerified, run = spawnDetached, execPath = process.execPath, pid = null } = {}) {
  if (kind === 'user') {
    const r = await installUserRelease(release, { log, fetchVerifiedImpl })
    return r.ok ? { ...r, then: 'watch' } : r
  }
  if (kind === 'inno') return installWindows(release, { log, fetchVerifiedImpl, run })
  if (kind === 'app') return installMac(release, { log, fetchVerifiedImpl, run, execPath, pid })
  return { ok: false, code: 'CANNOT_SELF_UPDATE', reason: kind === 'system' ? 'installed as a system package (root): update it with the system installer' : 'not installed with an installer: update it the way you installed it (npm, Docker…)' }
}

function spawnDetached (cmd, args, { log } = {}) {
  const child = spawn(cmd, args, { detached: true, windowsHide: true, stdio: 'ignore' })
  child.on('error', (e) => log?.(`[vault] update: could not start ${cmd}: ${e.message}`))
  child.unref()
}

/** Baja y verifica un archivo del release a una carpeta propia (que se vacía antes). */
async function downloadVerified (release, re, { log, fetchVerifiedImpl, work }) {
  const pick = pickAsset(release.assets, [{ kind: 'asset', re }])
  if (!pick.ok) return pick
  fs.rmSync(work, { recursive: true, force: true })
  fs.mkdirSync(work, { recursive: true, mode: 0o700 })
  const got = await fetchVerifiedImpl(pick.asset, { repo: REPO, product: 'dotrino-vault', version: VERSION, dir: work })
  if (got.ok) log(`[vault] update: ${pick.asset.name} verified against its attestation`)
  return got
}

/**
 * WINDOWS: el instalador nuevo, en silencio. Es lo único que puede cambiar los archivos: un
 * .exe en marcha no se sobrescribe. El instalador cierra lo que los usa (la bóveda, y la
 * ventana si está abierta), los reemplaza y vuelve a arrancar la bóveda (`--start-daemon`).
 * Las tareas elegidas al instalar (arrancar al iniciar sesión) se conservan.
 */
async function installWindows (release, { log, fetchVerifiedImpl, run }) {
  const work = updateWorkDir('win32')
  const got = await downloadVerified(release, /-windows-x64-setup\.exe$/, { log, fetchVerifiedImpl, work })
  if (!got.ok) return got
  run(got.file, ['/VERYSILENT', '/SUPPRESSMSGBOXES', '/NORESTART', '/FORCECLOSEAPPLICATIONS', `/LOG=${path.join(work, 'setup.log')}`], { log })
  log(`[vault] update: installer for ${release.version} started; it restarts the vault when it finishes`)
  return { ok: true, version: release.version, then: 'exit' }
}

/**
 * macOS: la app entera. Se descomprime al lado de la actual (misma carpeta, así el cambio es
 * un renombrado y no una copia a medias), se aparta la vieja, se pone la nueva y se borra la
 * vieja. Lo que está corriendo sigue con su copia hasta que se reinicia.
 *
 * Quien la levanta: launchd si la bóveda corre como agente (KeepAlive); si corre suelta, un
 * relanzador que espera a que este proceso se vaya y arranca el binario nuevo.
 */
async function installMac (release, { log, fetchVerifiedImpl, run, execPath, pid }) {
  const app = appBundleOf(execPath)
  if (!app) return { ok: false, code: 'CANNOT_SELF_UPDATE', reason: 'not running from Dotrino Vault.app' }
  const work = updateWorkDir('darwin')
  const got = await downloadVerified(release, /-macos-universal\.zip$/, { log, fetchVerifiedImpl, work })
  if (!got.ok) return got
  const parent = path.dirname(app)
  const stage = path.join(parent, `.dotrino-vault-update-${process.pid}`)
  fs.rmSync(stage, { recursive: true, force: true })
  try {
    try { execFileSync('ditto', ['-x', '-k', got.file, stage], { stdio: ['ignore', 'ignore', 'pipe'] }) } catch (e) {
      return { ok: false, code: 'UNPACK_FAILED', reason: `could not unpack the release: ${String(e.stderr || e.message).trim().split('\n').slice(-2).join(' · ')}` }
    }
    const newOne = path.join(stage, 'Dotrino Vault.app')
    if (!fs.existsSync(path.join(newOne, 'Contents', 'MacOS', 'dotrino-vaultd'))) return { ok: false, code: 'BAD_ARCHIVE', reason: 'the archive has no Dotrino Vault.app inside' }
    const oldOne = `${app}.old-${process.pid}`
    fs.renameSync(app, oldOne)
    try { fs.renameSync(newOne, app) } catch (e) {
      fs.renameSync(oldOne, app) // se deja como estaba
      return { ok: false, code: 'SWAP_FAILED', reason: `could not put the new app in place: ${e.message}` }
    }
    fs.rmSync(oldOne, { recursive: true, force: true })
  } finally {
    fs.rmSync(stage, { recursive: true, force: true })
    fs.rmSync(work, { recursive: true, force: true })
  }
  // Suelta (sin launchd): el relanzador espera a que `pid` se vaya y arranca el nuevo.
  if (pid && process.env.XPC_SERVICE_NAME !== 'com.dotrino.vault') {
    const bin = path.join(app, 'Contents', 'MacOS', 'dotrino-vaultd')
    const logFile = path.join(os.homedir(), '.local', 'share', 'dotrino', 'vault', 'daemon.log')
    run('/bin/sh', ['-c', 'while kill -0 "$1" 2>/dev/null; do sleep 0.5; done; exec "$2" >>"$3" 2>&1', 'relaunch', String(pid), bin, logFile], { log })
  }
  log(`[vault] update: ${release.version} installed in ${app}`)
  return { ok: true, version: release.version, then: 'exit' }
}
