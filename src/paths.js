/**
 * Resolución del directorio de datos y escritura de archivos con permisos
 * restrictivos (0600) **y cifrados en reposo**.
 *
 * `readJson`/`writeJson` aceptan un códec de reposo (`atRestFor(dir)`, ver
 * `atrest.js`): con él, el contenido del archivo NO queda en claro en el disco.
 * Lo usan TODOS los archivos de datos del vault —identidad, árbol de contenido
 * (`vault.json`), hilos y perfil (`threads.json`) y secretos de servicios
 * (`secrets.json`)—, no solo la identidad: el contenido del usuario merece el
 * mismo trato que la maestra. `decrypt` deja pasar el texto en claro, así que
 * una instalación anterior se lee igual y queda cifrada en la primera escritura.
 */
import os from 'node:os'
import path from 'node:path'
import fs from 'node:fs'

/**
 * Dir de datos del vault. Override con DOTRINO_VAULT_DIR.
 *
 * En Linux/macOS: `~/.local/share/dotrino/vault`. DEBE coincidir exactamente con la unit
 * systemd (`%h/.local/share/...` + ReadWritePaths) y con install.sh (DATA_DIR),
 * porque el CLI de control corre en la shell del usuario SIN el `Environment=` del
 * servicio: si difieren, `dotrino-vault status/pair/devices` no encuentra al daemon.
 *
 * En Windows: `%LOCALAPPDATA%\Dotrino\vault`, que es donde Windows espera los datos de
 * una app. El daemon y el CLI lo resuelven igual, así que el contrato por archivos entre
 * los dos (ver `vaultControl.js`) sigue funcionando sin tocar nada.
 */
export function dataDir () {
  if (process.env.DOTRINO_VAULT_DIR) return process.env.DOTRINO_VAULT_DIR
  if (process.platform === 'win32') {
    const base = process.env.LOCALAPPDATA || path.join(os.homedir(), 'AppData', 'Local')
    return path.join(base, 'Dotrino', 'vault')
  }
  return path.join(os.homedir(), '.local', 'share', 'dotrino', 'vault')
}

export function ensureDir (dir) {
  fs.mkdirSync(dir, { recursive: true, mode: 0o700 })
}

/** @param {{decrypt:(t:string)=>string}} [atRest] códec de reposo (`atRestFor(dir)`). */
export function readJson (file, fallback, atRest) {
  try {
    let text = fs.readFileSync(file, 'utf8')
    if (atRest) text = atRest.decrypt(text)
    return JSON.parse(text)
  } catch (_) { return fallback }
}

/**
 * Escritura atómica (tmp + rename) con modo 0600. Con `atRest`, el archivo se
 * escribe CIFRADO (nunca toca el disco en claro: se cifra antes del tmp).
 * @param {{encrypt:(t:string)=>string}} [atRest]
 */
export function writeJson (file, obj, atRest) {
  ensureDir(path.dirname(file))
  const text = JSON.stringify(obj, null, 2)
  const tmp = file + '.tmp'
  fs.writeFileSync(tmp, atRest ? atRest.encrypt(text) : text, { mode: 0o600 })
  fs.renameSync(tmp, file)
  try { fs.chmodSync(file, 0o600) } catch (_) {}
}
