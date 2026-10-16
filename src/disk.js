/**
 * EL DISCO DEL BINARIO: archivos de verdad bajo el directorio del perfil, en modo 0600 y
 * cifrados en reposo con la llave de esta máquina. Es la implementación de la interfaz de
 * `lib/src/core/disk.js` que usa el demonio; el navegador pone la suya.
 *
 * Todo lo que es de Node y de un sistema de archivos con permisos (el `chmod`, escribir
 * aparte y renombrar) vive aquí, y no en el núcleo, para que el núcleo sea el mismo código
 * en las tres bóvedas.
 */
import fs from 'node:fs'
import path from 'node:path'
import { atRestFor, kekFor } from './atrest.js'
import { ensureDir } from './paths.js'

/** El modo de un archivo que existía con otro más abierto (las bitácoras de antes de 0.89). */
function narrow (file) {
  try { if ((fs.statSync(file).mode & 0o077) !== 0) fs.chmodSync(file, 0o600) } catch (_) {}
}

export function nodeDisk (dir, { atRest = null } = {}) {
  ensureDir(dir)
  const at = (name) => path.join(dir, name)
  return {
    dir,
    read (name) {
      try { return fs.readFileSync(at(name), 'utf8') } catch (e) {
        if (e.code === 'ENOENT') return null
        throw e
      }
    },
    write (name, text) {
      const file = at(name)
      ensureDir(path.dirname(file))
      const tmp = file + '.tmp'
      fs.writeFileSync(tmp, text, { mode: 0o600 })
      fs.renameSync(tmp, file)
      narrow(file)
    },
    append (name, text) {
      const file = at(name)
      fs.appendFileSync(file, text, { mode: 0o600 })
      // El `mode` de `appendFileSync` solo aplica al CREAR.
      narrow(file)
    },
    exists: (name) => fs.existsSync(at(name)),
    remove: (name) => { fs.rmSync(at(name), { force: true }) },
    rename: (from, to) => { fs.renameSync(at(from), at(to)) },
    size: (name) => { try { return fs.statSync(at(name)).size } catch (_) { return 0 } },
    atRest: atRest || atRestFor(dir),
    machineKey: () => new Uint8Array(kekFor(dir))
  }
}

export default { nodeDisk }
