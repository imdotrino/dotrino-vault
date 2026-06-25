/**
 * Resolución del directorio de datos y escritura de archivos con permisos
 * restrictivos (0600). En v1 la clave maestra va en claro dentro de este dir
 * (la guarda `@dotrino/identity` en `identity.json`); 0600 evita que sea
 * world-readable. v2 añadirá cifrado en reposo con contraseña maestra.
 */
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'

/**
 * Dir de datos del vault. Override con DOTRINO_VAULT_DIR.
 * Default: ~/.local/share/dotrino/vault. DEBE coincidir exactamente con la unit
 * systemd (`%h/.local/share/...` + ReadWritePaths) y con install.sh (DATA_DIR),
 * porque el CLI de control corre en la shell del usuario SIN el `Environment=` del
 * servicio: si difieren, `dotrino-vault status/pair/devices` no encuentra al daemon.
 */
export function dataDir () {
  return process.env.DOTRINO_VAULT_DIR || path.join(os.homedir(), '.local', 'share', 'dotrino', 'vault')
}

export function ensureDir (dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
}

export function readJson (file, fallback) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')) } catch (_) { return fallback }
}

/** Escritura atómica (tmp + rename) con modo 0600. */
export function writeJson (file, obj) {
  ensureDir(path.dirname(file))
  const tmp = file + '.tmp'
  fs.writeFileSync(tmp, JSON.stringify(obj, null, 2), { mode: 0o600 })
  fs.renameSync(tmp, file)
  try { fs.chmodSync(file, 0o600) } catch (_) {}
}
