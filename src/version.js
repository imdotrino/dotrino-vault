/**
 * version.js — de dónde sale «la versión» según cómo se esté corriendo.
 *
 *   · binario SEA  → la inyecta esbuild al compilar (`__VAULT_VERSION__`).
 *   · npm / docker → se lee del `package.json` que viaja con el paquete.
 *   · desde el repo → lo mismo, así que deja de decir «dev» sin motivo.
 *
 * Importa: `dotrino-vault status` compara la versión del CLI con la del daemon para
 * avisar de que el servicio quedó viejo tras actualizar. Si las dos dicen «dev», ese
 * aviso no puede funcionar.
 */
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

function fromPackageJson () {
  try {
    const here = path.dirname(fileURLToPath(import.meta.url))
    return JSON.parse(fs.readFileSync(path.join(here, '..', 'package.json'), 'utf8')).version || 'dev'
  } catch (_) { return 'dev' }
}

// eslint-disable-next-line no-undef
export const VERSION = (typeof __VAULT_VERSION__ !== 'undefined') ? __VAULT_VERSION__ : fromPackageJson()

export default VERSION
