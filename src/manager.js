/**
 * manager.js — corre TODOS los perfiles del vault a la vez.
 *
 * Cada perfil es un `startVault` independiente: su propia maestra, su propio
 * directorio y su propia conexión al proxy (identificada con SU pubkey). Los N
 * conviven en el mismo daemon: los dispositivos se direccionan por pubkey, así
 * que el perfil «activo» NO limita el servicio —es solo el destino por defecto de
 * la CLI cuando no pasas `--profile`—. Un dispositivo enrolado en el perfil de
 * trabajo sigue funcionando mientras usas el personal, sin cambiar nada.
 */
import { startVault } from './vault.js'
import { openProfiles } from './profiles.js'
import { installNodeGlobals } from './node-globals.js'
import { dataDir, ensureDir } from './paths.js'
import { Identity } from '@dotrino/identity/node'
import { atRestFor } from './atrest.js'

/**
 * D12 (`docs/acta-de-perfil.md`): la bóveda **no** borra una cuenta que ella manda si
 * quedan otros miembros — antes tiene que pasarle el acta a un dispositivo conectado.
 * Es D6 ("perder el master es perder la cuenta") leído al derecho: con más miembros,
 * el que borra no la pierde solo para él.
 *
 * Pura a propósito (recibe el veredicto ya calculado) para poder probar la regla sin
 * levantar un vault entero.
 */
export function assertCanRemove ({ isMaster, memberCount, name = '' }) {
  if (!isMaster || memberCount <= 1) return true
  const others = memberCount - 1
  const e = new Error(
    `this vault is the master of account "${name}" and it has ${others} more device(s): ` +
    'hand the master over to one that is connected first. Deleting it like this leaves them ' +
    'with their key and nobody able to sign the record again.'
  )
  e.code = 'MASTER_WITH_MEMBERS'
  e.members = memberCount
  throw e
}

export async function startVaultManager ({ root = dataDir(), proxyUrl, log = console.log, onEnrollChallenge, autoLockMs } = {}) {
  ensureDir(root)
  // El keypair de transporte del proxy-client es del PROCESO, no de la identidad:
  // se instala apuntando a la RAÍZ (no al dir de un perfil) para que los perfiles
  // no se peleen por el archivo ni se lo lleven al borrarse.
  installNodeGlobals(root)

  const profiles = openProfiles(root, {
    ...(autoLockMs === undefined ? {} : { autoLockMs }),
    // Que se cierre solo tiene que VERSE: si no, quien vuelve y encuentra la consola
    // pidiendo la contraseña otra vez cree que algo se rompió.
    onAutoLock: (id) => log('[vault] profile %s locked itself after %d min idle (the console; devices keep working)',
      id, Math.round(profiles.autoLockMs / 60000))
  })
  /**
   * ACUÑAR (o simplemente LEER) la llave de una carpeta, y cerrarla enseguida.
   *
   * Existe porque el nombre de la carpeta sale de la llave y hay que saber cuál es antes
   * de poder ponérselo. La llave se genera en memoria y se escribe acto seguido —no hay
   * costura entre las dos cosas en `Identity.connect`—, así que se acuña donde sea y
   * después se mueve la carpeta.
   *
   * Se CIERRA (`destroy`) antes de devolver: quien llama va a renombrar la carpeta, y una
   * identidad abierta se quedó con la ruta vieja como texto.
   */
  async function mintKey (dir) {
    const identity = await Identity.connect({ dir, atRest: atRestFor(dir) })
    try {
      if (!identity.me?.publickey) await identity.setMyNickname('')
      return identity.me?.publickey || null
    } finally { try { identity.destroy() } catch (_) {} }
  }

  const migrated = await profiles.migrate(mintKey)
  if (migrated?.migrated) log('[vault] identidad mono-perfil migrada al perfil %s', migrated.id)

  const running = new Map() // id -> instancia de startVault

  async function open (id) {
    const p = profiles.get(id)
    const tag = p?.name ? `${p.name}` : id
    const v = await startVault({
      dir: profiles.dirOf(id),
      proxyUrl,
      log: (...a) => log(`[${tag}]`, ...a),
      isLocked: () => profiles.isLocked(id),
      // Para poder DECIR que este perfil no tiene contraseña, y por tanto que sus
      // variables privadas se abren con material que vive en este mismo disco.
      hasPassword: () => !!profiles.get(id)?.protected,
      // Para la consola remota: la contraseña llega dentro del sobre firmado y hay que
      // convertirla en la llave que abre la copia maestra de los secretos.
      deriveAdminKey: (password) => profiles.adminKey(id, password),
      // Camino A: nació para adoptar la cuenta de un aparato (ver profiles.add).
      forAdoption: !!p?.adopt,
      // Ya adoptó: la marca se consume (no vuelve a estar «a la espera»).
      onAdopted: () => { try { profiles.clearAdopt(id) } catch (_) {} },
      onEnrollChallenge: (info) => onEnrollChallenge?.({ ...info, profile: id, profileName: p?.name || '' })
    })
    running.set(id, v)
    return v
  }

  for (const p of profiles.list()) {
    // ANTES de abrir: la carpeta tiene que llamarse como su llave. Es toda la migración
    // (mover la data a la carpeta que le toca) y va aquí porque es el único momento en que
    // la identidad está cerrada — renombrarla abierta la deja escribiendo en la ruta vieja.
    let id = p.id
    try {
      id = await profiles.ensureNamedByKey(p.id, mintKey)
      if (id !== p.id) log('[vault] profile %s renamed to %s (the folder is named after its key)', p.id, id)
    } catch (e) { log('[vault] could not name the folder of %s after its key: %s', p.id, e.message) }
    try { await open(id) } catch (e) { log('[vault] no se pudo abrir el perfil %s: %s', id, e.message) }
  }

  const get = (id) => {
    const v = running.get(id)
    if (!v) throw new Error('profile is not open: ' + id)
    return v
  }

  /** Resumen para state.json / `profile ls`: identidad + candado de cada perfil. */
  const summary = () => profiles.list().map((p) => {
    const v = running.get(p.id)
    return { ...p, fingerprint: v?.fingerprint || null, iss: v?.master || null }
  })

  return {
    profiles,
    running,
    get,
    list: () => profiles.list(),
    summary,
    current: () => get(profiles.current()),
    currentId: () => profiles.current(),
    resolve: (ref) => profiles.resolve(ref),

    /**
     * Crea un perfil. Con `adopt: true` nace **vacío, esperando la cuenta de un aparato**
     * (camino A): la bóveda pone el sitio y la llave que entrará como miembro, pero la
     * cuenta la trae el dispositivo y se adopta al emparejar.
     */
    async add (name, { adopt = false, kek = null } = {}) {
      const p = await profiles.add(name, { adopt, kek, mintKey })
      await open(p.id)
      log('[vault] perfil creado%s: %s (%s)', adopt ? ' (a la espera de adoptar una cuenta)' : '', p.name || '(sin nombre)', p.id)
      return profiles.get(p.id)
    },

    /** Borra el perfil: cierra su conexión y elimina su maestra y sus datos. */
    async remove (ref) {
      const id = profiles.resolve(ref)
      // FRENO D12 (acta-de-perfil.md): si esta bóveda MANDA la cuenta y quedan otros
      // miembros, borrarla los deja con su llave y sin nadie que pueda volver a sellar
      // el acta: la cuenta muere para todos, en silencio. Primero se le pasa el mando
      // a un dispositivo conectado. (En el dispositivo no hay tal freno: allí borrar
      // se lleva su llave y su copia, y la cuenta sigue viva donde vive el master.)
      const v = running.get(id)
      if (v) {
        const [isMaster, record] = await Promise.all([
          v.isMaster().catch(() => false),
          v.profileMembers().catch(() => ({ members: [] }))
        ])
        assertCanRemove({ isMaster, memberCount: (record?.members || []).length, name: profiles.get(id)?.name || id })
      } else {
        log('[vault] profile %s is not open: deleting without being able to check its record', id)
      }
      const res = profiles.remove(id) // valida: no es el único, no está bloqueado
      try { running.get(id)?.close() } catch (_) {}
      running.delete(id)
      log('[vault] perfil borrado: %s (%s)', res.name || '(sin nombre)', id)
      return res
    },

    close () { for (const v of running.values()) { try { v.close() } catch (_) {} } running.clear() }
  }
}
