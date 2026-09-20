/**
 * update.js — ENTERARSE DE QUE HAY VERSIÓN NUEVA, Y TRAERLA CUANDO EL DUEÑO LO DIGA.
 *
 * Lo que costó una tarde el 2026-09-19 no fue instalar: fueron tres comandos. Fue NO
 * ENTERARSE. El replicador de Cepi llevaba quince días en 0.98.0 y las dos bóvedas en
 * 0.121.0 con la 0.123.0 publicada, y nada en ninguna pantalla lo decía. `status` solo
 * avisa cuando el daemon corriendo es más viejo que el CLI instalado — o sea cuando ya
 * actualizaste y falta reiniciar—, nunca de que el mundo siguió.
 *
 * POR QUÉ ESTO NO DESCARGA SOLO, y no es pereza:
 *
 *   > no existe ningún interruptor remoto. Nadie —tampoco Dotrino— puede dejar sin
 *   > funcionar el software que alguien se instaló en su máquina.   (CLAUDE.md)
 *
 * Un auto-descargador es esa misma puerta en el otro sentido: un canal por el que meter
 * código nuevo en la máquina que guarda la maestra, sin que nadie diga que sí. Si el
 * pipeline de release se compromete, cada bóveda se lo traga sola. Así que se parte en
 * dos, y la mitad automática es la que no puede hacer daño:
 *
 *   · MIRAR (esto, y el daemon una vez al día) — una lectura. No puede romper nada.
 *   · TRAER E INSTALAR (`dotrino-vault update`) — lo escribe una persona.
 *
 * Y lo que se trae SE VERIFICA antes de tocar el disco: cada `.deb` y cada `.tar.gz` sale
 * del release con una atestación de sigstore que lo ata a su commit y a su workflow. Sin
 * esa comprobación no se instala nada — no hay repliegue a «bueno, lo bajé de la URL
 * correcta», que es exactamente lo que cree quien ya está siendo atacado.
 */
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { VERSION } from './version.js'

export const REPO = 'imdotrino/dotrino-vault'
const RELEASES = `https://api.github.com/repos/${REPO}/releases/latest`

/** Cada cuánto mira el daemon. Una vez al día sobra: esto no es una carrera. */
export const CHECK_EVERY_MS = 24 * 60 * 60_000

/** `0.123.0` → `[0,123,0]`, y lo que no sea eso no compite. */
const parts = (v) => String(v || '').trim().replace(/^v/, '').split('.').map((n) => parseInt(n, 10))
const valid = (v) => parts(v).length === 3 && parts(v).every((n) => Number.isFinite(n))

/** ¿`a` es más nueva que `b`? Sin dependencias: son tres números. */
export function isNewer (a, b) {
  if (!valid(a) || !valid(b)) return false
  const [x, y, z] = parts(a); const [p, q, r] = parts(b)
  return x !== p ? x > p : y !== q ? y > q : z > r
}

/**
 * La última versión publicada, preguntándoselo a GitHub.
 *
 * Devuelve `{ ok: false, reason }` cuando no se pudo mirar, y NO se confunde con «estás al
 * día»: son cosas distintas y quien lo enseña tiene que poder decir cuál es. Sin red, sin
 * respuesta o con una respuesta rara, esto no inventa nada.
 */
export async function latestRelease ({ fetchImpl = fetch, timeoutMs = 10_000 } = {}) {
  const ac = new AbortController()
  const t = setTimeout(() => ac.abort(), timeoutMs)
  try {
    const r = await fetchImpl(RELEASES, {
      signal: ac.signal,
      headers: { accept: 'application/vnd.github+json', 'user-agent': `dotrino-vault/${VERSION}` }
    })
    if (!r.ok) return { ok: false, reason: `github answered ${r.status}` }
    const d = await r.json()
    const version = String(d?.tag_name || '').replace(/^v/, '')
    if (!valid(version)) return { ok: false, reason: `unreadable tag: ${d?.tag_name}` }
    const assets = (d.assets || []).map((a) => ({ name: a.name, url: a.browser_download_url, size: a.size }))
    return { ok: true, version, assets, url: d.html_url }
  } catch (e) {
    return { ok: false, reason: e.name === 'AbortError' ? 'timed out' : e.message }
  } finally { clearTimeout(t) }
}

/**
 * Qué archivo le toca a ESTA máquina. El `.deb` solo donde hay `dpkg`; en cualquier otro
 * Linux, el tarball. Fuera de Linux no se emite binario, y se dice en vez de bajar algo que
 * no sirve.
 */
export function assetFor (assets, { platform = process.platform, arch = process.arch, hasDpkg = null } = {}) {
  if (platform !== 'linux') return { ok: false, reason: `there is no binary for ${platform}: update with npm (npx @dotrino/vaultd)` }
  if (arch !== 'x64') return { ok: false, reason: `there is no binary for ${arch}` }
  const deb = hasDpkg === null ? fs.existsSync('/usr/bin/dpkg') : hasDpkg
  const want = deb ? /_amd64\.deb$/ : /-linux-x64\.tar\.gz$/
  const found = assets.find((a) => want.test(a.name))
  if (!found) return { ok: false, reason: `the release has no ${deb ? '.deb' : 'tarball'}` }
  return { ok: true, asset: found, kind: deb ? 'deb' : 'tar' }
}

/**
 * LO QUE SE BAJA SE COMPRUEBA, y si no se puede comprobar NO SE INSTALA.
 *
 * `gh attestation verify` contrasta el archivo contra la atestación que sigstore guarda de
 * esa compilación: ata el binario a su commit y a su workflow. Que la URL sea la buena no
 * prueba nada — quien está siendo atacado también cree que su URL es la buena.
 *
 * Sin `gh` no hay con qué verificar, así que se para y se dice cómo. Es feo y es correcto.
 */
export function verifyArtifact (file, { run = execFileSync } = {}) {
  try { run('gh', ['--version'], { stdio: 'ignore' }) } catch (_) {
    return { ok: false, reason: 'gh is not installed, so the download cannot be verified: install GitHub CLI, or verify it by hand with `gh attestation verify`' }
  }
  try {
    const out = run('gh', ['attestation', 'verify', file, '--repo', REPO], { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] })
    return { ok: true, out: String(out || '').trim() }
  } catch (e) {
    return { ok: false, reason: `the signature does not check out: ${String(e.stderr || e.message).trim().slice(0, 300)}` }
  }
}

/** Baja el archivo a un directorio temporal propio y devuelve dónde quedó. */
export async function download (asset, { fetchImpl = fetch, dir = null } = {}) {
  const dest = dir || fs.mkdtempSync(path.join(os.tmpdir(), 'dotrino-update-'))
  const file = path.join(dest, asset.name)
  const r = await fetchImpl(asset.url, { headers: { 'user-agent': `dotrino-vault/${VERSION}` }, redirect: 'follow' })
  if (!r.ok) throw Object.assign(new Error(`download failed: ${r.status}`), { code: 'DOWNLOAD_FAILED' })
  fs.writeFileSync(file, Buffer.from(await r.arrayBuffer()), { mode: 0o644 })
  return file
}
