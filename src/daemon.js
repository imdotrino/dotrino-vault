/**
 * daemon.js — modo SERVICIO del vault. Arranca TODOS los perfiles del usuario
 * (`manager.js`) y expone control LOCAL por archivos + señales (sin socket/puerto:
 * nada escucha en red).
 *
 *   state.json          perfiles + fingerprint/iss de cada uno (lo lee el CLI/instalador)
 *   SIGUSR1 → pair.json  inicia un emparejamiento y vuelca el QR
 *   pending-enroll.json  cuando un dispositivo pide enrolarse: { deviceId } a
 *                        aprobar (emparejamiento ENDURECIDO, ver docs/)
 *   SIGUSR2 → consume approve/reject/revoke/secret/profile-request y vuelca
 *             devices.json / secrets-list.json / profiles-list.json
 *
 * MULTI-PERFIL: cada petición de la CLI trae a qué perfil apunta (`profile`); si
 * no lo trae, va al perfil activo. La maestra del perfil solo firma el cert de un
 * dispositivo DESPUÉS de `dotrino-vault approve`.
 */
import fs from 'node:fs'
import path from 'node:path'
import { startVaultManager } from './manager.js'
import { dataDir, writeJson, readJson } from './paths.js'
import { VERSION } from './version.js'

const readJsonSafe = (f) => readJson(f, null)
const rm = (f) => { try { fs.rmSync(f, { force: true }) } catch (_) {} }

/**
 * UNA sola bóveda por directorio de datos.
 *
 * El dir NO depende de la carpeta desde la que lances el comando: es fijo por usuario
 * (`%LOCALAPPDATA%\\Dotrino\\vault` o `~/.local/share/dotrino/vault`). Así que lanzar el
 * comando dos veces —en dos ventanas, sin darse cuenta— daba DOS daemons sobre los mismos
 * datos, los dos con tu identidad y los dos conectados al proxy; el segundo pisaba el pid
 * de `state.json`, así que el CLI solo le hablaba a uno y el otro quedaba de fantasma.
 *
 * El candado es el propio `state.json`: si el pid que hay sigue vivo, no arrancamos. Un
 * pid muerto (se cortó la luz) no estorba. Con `DOTRINO_VAULT_DIR` distintos conviven
 * cuantas quieras: lo que colisiona es el directorio, no el programa.
 */
function comprobarInstanciaUnica (dir) {
  let s = null
  try { s = JSON.parse(fs.readFileSync(path.join(dir, 'state.json'), 'utf8')) } catch (_) { return }
  const pid = Number(s?.pid)
  if (!pid || pid === process.pid) return
  try { process.kill(pid, 0) } catch (_) { return } // no existe: el candado es de un muerto
  console.error('Ya hay una bóveda corriendo sobre estos datos (proceso %d).', pid)
  console.error('  datos: %s', dir)
  console.error('Dos bóvedas sobre el mismo directorio se pisan: párá la otra, o usa')
  console.error('DOTRINO_VAULT_DIR para darle a esta un directorio propio.')
  process.exit(3)
}

export async function runDaemon () {
  const dir = dataDir()
  const proxyUrl = process.env.PROXY_URL || 'wss://proxy.dotrino.com'
  comprobarInstanciaUnica(dir)

  const pendingEnrollFile = path.join(dir, 'pending-enroll.json')
  // Cuando un dispositivo pide enrolarse, exponemos su deviceId (y a QUÉ perfil
  // quiere entrar) para que el dueño lo compare con el del dispositivo y apruebe.
  const onEnrollChallenge = ({ deviceId, scope, profile, profileName }) => {
    writeJson(pendingEnrollFile, { v: 2, at: Date.now(), deviceId, scope, profile, profileName })
  }

  const mgr = await startVaultManager({ root: dir, proxyUrl, onEnrollChallenge })

  // --- state.json ---
  const stateFile = path.join(dir, 'state.json')
  const daemonVersion = VERSION
  // Los campos de la raíz (fingerprint/iss) son los del perfil ACTIVO: los leen el
  // instalador y la web, que son anteriores al multi-perfil. La lista completa va
  // en `profiles`.
  const writeState = () => {
    const cur = mgr.summary().find((p) => p.current) || {}
    writeJson(stateFile, {
      v: 2, version: daemonVersion, fingerprint: cur.fingerprint || null, iss: cur.iss || null,
      proxy: proxyUrl, pid: process.pid, startedAt: new Date().toISOString(),
      current: mgr.currentId(), profiles: mgr.summary()
    })
  }
  writeState()
  const profilesFile = path.join(dir, 'profiles-list.json')
  const dumpProfiles = (extra = {}) => { writeState(); writeJson(profilesFile, { v: 1, at: Date.now(), current: mgr.currentId(), profiles: mgr.summary(), ...extra }) }

  console.log(`dotrino-vault · datos en ${dir} · proxy ${proxyUrl}`)
  for (const p of mgr.summary()) {
    console.log(`perfil ${p.current ? '*' : ' '} ${p.name || '(sin nombre)'} · ${p.id} · ${p.fingerprint}${p.protected ? (p.locked ? ' · 🔒 bloqueado' : ' · 🔓 desbloqueado') : ''}`)
  }

  /** Perfil destino de una petición de la CLI (o el activo si no lo dice). */
  const resolveTarget = (req) => {
    try {
      const id = req?.profile ? mgr.resolve(req.profile) : mgr.currentId()
      return { id, vault: mgr.get(id) }
    } catch (e) { console.error('[vault] perfil inválido en la petición:', e.message); return null }
  }
  const targetOf = (req) => resolveTarget(req)?.vault || null

  // --- SIGUSR1: iniciar emparejamiento ---
  const pairFile = path.join(dir, 'pair.json')
  const pairReqFile = path.join(dir, 'pair-request.json')
  async function atenderEmparejamiento () {
    try {
      rm(pendingEnrollFile)
      // Pairing manual por CLI = gesto explícito del dueño → cert de identidad completo.
      // ttlMs: 30 días (MAX_DELEGATION_MS). Sin esto caía al default de 24 h, pensado
      // para delegaciones efímeras: los dispositivos emparejados morían al día
      // siguiente en silencio ("no autorizado" en todas las apps). La renovación
      // automática la maneja `handleRenew`.
      const DEVICE_TTL_MS = 30 * 24 * 60 * 60 * 1000
      // `pair --service <ns>` (vía pair-request.json): cert SOLO con
      // vault:secrets:<ns> — para enrolar un SERVICIO (proxy, geo…) que lee sus
      // secretos, sin poder firmar como el usuario ni leer sus datos.
      const pairReq = readJsonSafe(pairReqFile); rm(pairReqFile)
      const vault = targetOf(pairReq)
      if (!vault) return
      const profileId = pairReq?.profile ? mgr.resolve(pairReq.profile) : mgr.currentId()
      const isService = typeof pairReq?.service === 'string' && pairReq.service
      const scope = isService ? ['vault:secrets:' + pairReq.service] : ['vault:sign', 'vault:read', 'vault:store']
      const label = pairReq?.label || (isService ? 'servicio:' + pairReq.service : 'cli')
      const { qr, expiresInMs } = vault.startPairing({ scope, label, ttlMs: DEVICE_TTL_MS })
      // `profile`/`profileName`: la CUENTA del vault a la que entra el dispositivo.
      // Con varias bóvedas en el mismo daemon, el QR sale de UNA y quien empareja
      // tiene que verlo (lo muestran la TUI y `dotrino-vault pair`).
      const profileName = mgr.profiles.get(profileId)?.name || ''
      writeJson(pairFile, { v: 2, qr, expiresAt: Date.now() + expiresInMs, profile: profileId, profileName })
      // El token es un secreto efímero: no debe quedar en disco más allá de su
      // vida. Se borra al VENCER (aquí) y al APROBARSE (abajo, consumido).
      const tok = qr.token
      setTimeout(() => {
        const cur = readJsonSafe(pairFile)
        if (cur?.qr?.token === tok) rm(pairFile)
      }, expiresInMs + 1000).unref?.()
      console.log('[vault] emparejamiento iniciado (válido %d min)', expiresInMs / 60000)
    } catch (e) {
      console.error('[vault] no se pudo iniciar emparejamiento:', e.message)
    }
  }

  // --- SIGUSR2: approve / reject / revoke / secretos / perfiles + volcados ---
  const devFile = path.join(dir, 'devices.json')
  const approveReqFile = path.join(dir, 'approve-request.json')
  const rejectReqFile = path.join(dir, 'reject-request.json')
  const revokeReqFile = path.join(dir, 'revoke-request.json')
  const secretReqFile = path.join(dir, 'secret-request.json')
  const secretsListFile = path.join(dir, 'secrets-list.json')
  const profileReqFile = path.join(dir, 'profile-request.json')
  const dumpReqFile = path.join(dir, 'dump-request.json')

  /**
   * Órdenes de perfil (crear/renombrar/borrar/activar) y del candado
   * (unlock/lock/password). La contraseña llega en un archivo 0600 dentro del dir
   * 0700 del vault y se BORRA al consumirla — mismo camino que ya usan los
   * secretos, y así nunca pasa por `ps` ni por el historial de la shell.
   */
  async function handleProfileRequest (req) {
    const ref = () => mgr.resolve(req.profile || mgr.currentId())
    switch (req.op) {
      case 'list': return {} // el volcado de perfiles ya se hace abajo
      case 'add': { const p = await mgr.add(req.name); return { done: `perfil creado: ${p.name || p.id}` } }
      case 'rm': { const r = await mgr.remove(req.profile); return { done: `perfil borrado: ${r.name || r.id}` } }
      case 'rename': { const p = mgr.profiles.rename(ref(), req.name); return { done: `perfil renombrado: ${p.name}` } }
      case 'use': { const p = mgr.profiles.setCurrent(ref()); return { done: `perfil activo: ${p.name || p.id}` } }
      case 'unlock': { await mgr.profiles.unlock(ref(), req.password); return { done: 'perfil desbloqueado' } }
      case 'lock': { mgr.profiles.lock(ref()); return { done: 'perfil bloqueado' } }
      case 'password-set': { await mgr.profiles.setPassword(ref(), req.password); return { done: 'contraseña guardada' } }
      case 'password-rm': { mgr.profiles.removePassword(ref()); return { done: 'contraseña quitada' } }
      default: throw new Error('operación de perfil desconocida: ' + req.op)
    }
  }

  async function atenderPeticiones () {
    try {
      const appr = readJsonSafe(approveReqFile)
      if (appr?.code) {
        try {
          const vault = targetOf(appr)
          const r = await vault.approveDevice(appr.code); rm(pendingEnrollFile); rm(pairFile); console.log('[vault] aprobado %s', r.deviceId)
        } catch (e) { console.error('[vault] aprobación falló:', e.message) }
        rm(approveReqFile)
      }
      const rej = readJsonSafe(rejectReqFile)
      if (rej?.deviceId) {
        try { targetOf(rej)?.rejectDevice(rej.deviceId); rm(pendingEnrollFile) } catch (_) {}
        rm(rejectReqFile)
      }
      // Cambio de permisos de un miembro del acta (`dotrino-vault caps`).
      const capsReq = readJsonSafe(path.join(dir, 'caps-request.json'))
      if (capsReq?.pub && Array.isArray(capsReq.caps)) {
        rm(path.join(dir, 'caps-request.json'))
        try {
          await targetOf(capsReq)?.setCaps(capsReq.pub, capsReq.caps)
          console.log('[vault] permisos actualizados: %s', capsReq.caps.join(', ') || '(ninguno)')
        } catch (e) { console.error('[vault] no se pudieron cambiar los permisos:', e.message) }
      }
      const req = readJsonSafe(revokeReqFile)
      if (req?.nonce) {
        try { await targetOf(req)?.revokeDevice(req.nonce); console.log('[vault] revocado nonce=%s', req.nonce) }
        catch (e) { console.error('[vault] revocación falló:', e.message) }
        rm(revokeReqFile)
      }
      // Secretos de servicios: `secret set/rm` del CLI. El archivo con el valor
      // vive un instante en el mismo dir 0700 del vault y se borra al consumir.
      const sec = readJsonSafe(secretReqFile)
      if (sec?.op) {
        rm(secretReqFile)
        try {
          const vault = targetOf(sec)
          if (sec.op === 'set') { vault.setSecret(sec.ns, sec.key, sec.value); console.log('[vault] secreto guardado: %s/%s', sec.ns, sec.key) }
          else if (sec.op === 'rm') { vault.deleteSecret(sec.ns, sec.key); console.log('[vault] secreto borrado: %s/%s', sec.ns, sec.key) }
        } catch (e) { console.error('[vault] secreto falló:', e.message) }
      }
      // Perfiles / candado.
      const preq = readJsonSafe(profileReqFile)
      if (preq?.op) {
        rm(profileReqFile) // lleva la contraseña: fuera del disco cuanto antes
        let extra = {}
        try { extra = await handleProfileRequest(preq) }
        catch (e) { extra = { error: e.message }; console.error('[vault] perfil: %s', e.message) }
        dumpProfiles(extra)
      } else {
        dumpProfiles()
      }
      // Volcados que lee la CLI (`devices`, `secret list`). A QUÉ perfil miran lo
      // dice dump-request.json; sin él, al activo.
      const dumpReq = readJsonSafe(dumpReqFile); rm(dumpReqFile)
      const t = resolveTarget(dumpReq || appr || rej || req || sec || {}) || { id: mgr.currentId(), vault: mgr.current() }
      // Nombres de secretos, nunca valores.
      writeJson(secretsListFile, { v: 1, at: Date.now(), profile: t.id, ns: t.vault.listSecrets() })
      writeJson(devFile, { v: 1, at: Date.now(), profile: t.id, ...(await t.vault.listDevices()) })
      // Acta del perfil: quién es del perfil y qué puede hacer cada uno (`members`/`caps`).
      try { writeJson(path.join(dir, 'acta.json'), { v: 1, at: Date.now(), profile: t.id, ...(await t.vault.profileMembers()) }) } catch (_) {}
    } catch (e) {
      console.error('[vault] error en señal de control:', e.message)
    }
  }

  // --- CÓMO LLEGAN LAS ÓRDENES DEL CLI ---
  //
  // El CLI escribe un archivo de petición en el dir de datos y hay que despertar al
  // daemon para que lo lea. Durante mucho tiempo eso fue una SEÑAL (SIGUSR1/SIGUSR2), y
  // por eso el vault no servía de nada en Windows: ahí esas señales no existen, así que
  // `pair`, `approve`, `members` y la TUI no podían pedirle nada al daemon. El `status`
  // engañaba, porque solo lee un archivo.
  //
  // Ahora la campanita es VIGILAR LA CARPETA (`fs.watch`), que funciona en los tres
  // sistemas, más un repaso periódico por si el watcher se pierde un evento (pasa en
  // carpetas de red y en algunos montajes). Las señales se mantienen donde existen: no
  // estorban y hacen que la respuesta sea inmediata.
  const REPASO_MS = 2000
  let atendiendo = false
  async function atender () {
    if (atendiendo) return          // una a la vez: las peticiones se consumen y se borran
    atendiendo = true
    try {
      // OJO: `fs.watch` avisa al CREAR el archivo, antes de que el CLI termine de
      // escribirlo. Si se lee a medias, el JSON no parsea y la petición se pierde con
      // sus datos — y el emparejamiento salía como si fuera de un dispositivo normal,
      // sin el `--service`, emitiendo un cert con el scope equivocado. Así que solo se
      // atiende cuando el archivo YA parsea; si no, lo recoge el repaso de 2 s.
      if (readJsonSafe(pairReqFile)) await atenderEmparejamiento()
      await atenderPeticiones()
    } catch (e) { console.error('[vault] error atendiendo una petición:', e.message) }
    finally { atendiendo = false }
  }

  try {
    fs.watch(dir, (_ev, file) => { if (!file || /-request\.json$/.test(file)) atender() })
  } catch (e) {
    console.error('[vault] no se pudo vigilar %s (%s); se atenderá solo por repaso', dir, e.message)
  }
  const repaso = setInterval(atender, REPASO_MS)
  repaso.unref?.()

  // POSIX: la señal sigue valiendo como atajo inmediato. En Windows no existe y no pasa nada.
  // Van por `atender()` y NO llaman directo: si no, la señal y el vigilante corren a la
  // vez, la primera consume la petición y la segunda la lee vacía — y un `pair --service`
  // acababa emitiendo un cert de dispositivo normal, con el scope equivocado.
  if (process.platform !== 'win32') {
    process.on('SIGUSR1', () => { atender() })
    process.on('SIGUSR2', () => { atender() })
  }

  // --- apagado limpio ---
  const shutdown = (sig) => {
    console.log(`\n[vault] ${sig} → deteniendo…`)
    rm(pairFile); rm(pendingEnrollFile)
    try { mgr.close() } catch (_) {}
    process.exit(0)
  }
  process.on('SIGTERM', () => shutdown('SIGTERM'))
  process.on('SIGINT', () => shutdown('SIGINT'))

  console.log('[vault] servicio listo.')
  return mgr
}
