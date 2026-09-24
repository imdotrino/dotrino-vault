/**
 * LA BÓVEDA SE ACTUALIZA SOLA, SIN SUDO, SI ESTÁ INSTALADA COMO USUARIO (dueño, 2026-09-24).
 *
 * Los binarios viven en `~/.local/share/dotrino/bin` (la única carpeta del home que la
 * unidad deja escribir). Lo que se prueba: que solo se actualiza desde ahí, que lo que no
 * verifica no toca nada, y que el cambio es atómico (nunca queda un binario a medias).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { execFileSync } from 'node:child_process'
import { isUserInstall, userBinDir, installUserRelease } from '../src/update.js'

const tmp = (n) => fs.mkdtempSync(path.join(os.tmpdir(), n))

test('solo es instalación de usuario si el binario corre desde ~/.local/share/dotrino/bin', () => {
  const home = '/home/x'
  assert.equal(userBinDir(home), '/home/x/.local/share/dotrino/bin')
  assert.equal(isUserInstall('/home/x/.local/share/dotrino/bin/dotrino-vaultd', home), true)
  assert.equal(isUserInstall('/usr/bin/dotrino-vaultd', home), false, 'el .deb es de root: no se toca')
  assert.equal(isUserInstall('/home/x/.local/bin/dotrino-vaultd', home), false, 'esa carpeta la unidad no la deja escribir')
})

/** Un tarball como el del release, con dos «binarios» de texto. */
function tarball (version, contenido) {
  const dir = tmp('rel-')
  const top = path.join(dir, `dotrino-vault-${version}-linux-x64`)
  fs.mkdirSync(top)
  fs.writeFileSync(path.join(top, 'dotrino-vaultd'), contenido + ' daemon')
  fs.writeFileSync(path.join(top, 'dotrino-vault'), contenido + ' cli')
  const file = path.join(tmp('dl-'), `dotrino-vault-${version}-linux-x64.tar.gz`)
  execFileSync('tar', ['czf', file, '-C', dir, path.basename(top)])
  return file
}

const release = (v) => ({ version: v, assets: [
  { name: `dotrino-vault_${v}_amd64.deb`, url: 'u1' },
  { name: `dotrino-vault-${v}-linux-x64.tar.gz`, url: 'u2' }
] })

test('verificado: reemplaza los dos binarios, con el tarball y no el .deb', async () => {
  const binDir = tmp('bin-')
  fs.writeFileSync(path.join(binDir, 'dotrino-vaultd'), 'viejo daemon')
  let pedido = null
  const res = await installUserRelease(release('9.9.9'), {
    binDir,
    fetchVerifiedImpl: async (asset) => { pedido = asset; return { ok: true, file: tarball('9.9.9', 'nuevo') } }
  })
  assert.equal(res.ok, true)
  assert.match(pedido.name, /-linux-x64\.tar\.gz$/, 'la instalación de usuario usa el tarball')
  assert.equal(fs.readFileSync(path.join(binDir, 'dotrino-vaultd'), 'utf8'), 'nuevo daemon')
  assert.equal(fs.readFileSync(path.join(binDir, 'dotrino-vault'), 'utf8'), 'nuevo cli')
  assert.equal(fs.statSync(path.join(binDir, 'dotrino-vaultd')).mode & 0o777, 0o755)
  assert.deepEqual(fs.readdirSync(binDir).filter((f) => f.endsWith('.new')), [], 'no quedan temporales')
})

test('lo que no verifica NO toca nada, y se dice por qué', async () => {
  const binDir = tmp('bin-')
  fs.writeFileSync(path.join(binDir, 'dotrino-vaultd'), 'viejo daemon')
  const res = await installUserRelease(release('9.9.9'), {
    binDir,
    fetchVerifiedImpl: async () => ({ ok: false, code: 'NO_ATTESTATION', reason: 'GitHub has no attestation', file: '/tmp/x' })
  })
  assert.equal(res.ok, false)
  assert.equal(res.code, 'NO_ATTESTATION')
  assert.equal(fs.readFileSync(path.join(binDir, 'dotrino-vaultd'), 'utf8'), 'viejo daemon')
})

test('un release sin tarball se dice, no se inventa', async () => {
  const res = await installUserRelease({ version: '9.9.9', assets: [{ name: 'dotrino-vault_9.9.9_amd64.deb', url: 'u' }] }, {
    binDir: tmp('bin-'), fetchVerifiedImpl: async () => { throw new Error('no debería bajar nada') }
  })
  assert.equal(res.ok, false)
})
