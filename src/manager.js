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

export async function startVaultManager ({ root = dataDir(), proxyUrl, log = console.log, onEnrollChallenge } = {}) {
  ensureDir(root)
  // El keypair de transporte del proxy-client es del PROCESO, no de la identidad:
  // se instala apuntando a la RAÍZ (no al dir de un perfil) para que los perfiles
  // no se peleen por el archivo ni se lo lleven al borrarse.
  installNodeGlobals(root)

  const profiles = openProfiles(root)
  const migrated = profiles.migrate()
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
    try { await open(p.id) } catch (e) { log('[vault] no se pudo abrir el perfil %s: %s', p.id, e.message) }
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
    async add (name, { adopt = false } = {}) {
      const p = profiles.add(name, { adopt })
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
