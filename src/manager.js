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
    if (!v) throw new Error('el perfil no está abierto: ' + id)
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

    async add (name) {
      const p = profiles.add(name)
      await open(p.id)
      log('[vault] perfil creado: %s (%s)', p.name || '(sin nombre)', p.id)
      return profiles.get(p.id)
    },

    /** Borra el perfil: cierra su conexión y elimina su maestra y sus datos. */
    async remove (ref) {
      const id = profiles.resolve(ref)
      const res = profiles.remove(id) // valida: no es el único, no está bloqueado
      try { running.get(id)?.close() } catch (_) {}
      running.delete(id)
      log('[vault] perfil borrado: %s (%s)', res.name || '(sin nombre)', id)
      return res
    },

    close () { for (const v of running.values()) { try { v.close() } catch (_) {} } running.clear() }
  }
}
