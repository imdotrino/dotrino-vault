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
import { latestVersion, isNewer, CHECK_EVERY_MS } from '@dotrino/update'
import { pickAsset, download, verifyArtifact as verify } from '@dotrino/update/fetch'
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
