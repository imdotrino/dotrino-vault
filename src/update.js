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
import { execFileSync } from 'node:child_process'
import { latestVersion, isNewer, CHECK_EVERY_MS } from '@dotrino/update'
import { pickAsset, download, verifyArtifact as verify, fetchVerified } from '@dotrino/update/fetch'
import { VERSION } from './version.js'

export const REPO = 'imdotrino/dotrino-vault'
export { isNewer, CHECK_EVERY_MS, download }

/** La última release del vault. `{ ok:false, reason }` si no se pudo mirar, que NO es «al día». */
export const latestRelease = (opts = {}) =>
  latestVersion({ source: 'github', repo: REPO, product: 'dotrino-vault', version: VERSION, ...opts })

/**
 * Qué archivo le toca a esta máquina. El `.deb` donde hay `dpkg`; en cualquier otro Linux,
 * el tarball. Fuera de Linux no se emite binario, y se dice en vez de bajar algo inútil.
 */
export function assetFor (assets, { platform = process.platform, arch = process.arch, hasDpkg = null } = {}) {
  if (platform !== 'linux') return { ok: false, reason: `there is no binary for ${platform}: update with npm (npx @dotrino/vaultd)` }
  if (arch !== 'x64') return { ok: false, reason: `there is no binary for ${arch}` }
  const deb = hasDpkg === null ? fs.existsSync('/usr/bin/dpkg') : hasDpkg
  return pickAsset(assets, [
    { kind: 'deb', re: /_amd64\.deb$/, when: () => deb },
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
  const got = await fetchVerifiedImpl(pick.asset, { repo: REPO, product: 'dotrino-vault', version: VERSION })
  if (!got.ok) return got
  log(`[vault] update: ${pick.asset.name} verified against its attestation`)
  const work = path.dirname(got.file)
  execFileSync('tar', ['xzf', got.file, '-C', work])
  const src = fs.readdirSync(work).map((d) => path.join(work, d)).find((d) => fs.existsSync(path.join(d, 'dotrino-vaultd')))
  if (!src) return { ok: false, code: 'BAD_TARBALL', reason: 'the tarball has no dotrino-vaultd inside' }
  fs.mkdirSync(binDir, { recursive: true })
  // El CLI primero y el daemon al final: cambiar el daemon es lo que dispara el reinicio.
  for (const name of ['dotrino-vault', 'dotrino-vaultd']) {
    const tmp = path.join(binDir, `.${name}.new`)
    fs.copyFileSync(path.join(src, name), tmp)
    fs.chmodSync(tmp, 0o755)
    fs.renameSync(tmp, path.join(binDir, name))
  }
  try { fs.rmSync(work, { recursive: true, force: true }) } catch (_) {}
  return { ok: true, version: release.version }
}
