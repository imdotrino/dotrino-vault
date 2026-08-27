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
function assertSingleInstance (dir) {
  let s = null
  try { s = JSON.parse(fs.readFileSync(path.join(dir, 'state.json'), 'utf8')) } catch (_) { return }
  const pid = Number(s?.pid)
  if (!pid || pid === process.pid) return
  try { process.kill(pid, 0) } catch (_) { return } // no existe: el candado es de un muerto
  console.error('A vault is already running on this data (process %d).', pid)
  console.error('  data: %s', dir)
  console.error('Two vaults on the same directory step on each other: stop the other one,')
  console.error('or use DOTRINO_VAULT_DIR to give this one its own directory.')
  process.exit(3)
}

export async function runDaemon () {
  const dir = dataDir()
  const proxyUrl = process.env.PROXY_URL || 'wss://proxy.dotrino.com'
  assertSingleInstance(dir)

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
  // `req: null` VA SIEMPRE, aunque nadie haya pedido nada: el daemon vuelca esta lista
  // también por su cuenta (cada repaso, y al atender cualquier otra cosa), y quien espera
  // respuesta tiene que poder distinguir «este volcado no contesta a nadie» de «este
  // contesta a lo mío». Sin esa marca, un repaso que caía en medio pasaba por respuesta:
  // el `unlock` se daba por hecho con la foto de cuando aún estaba cerrada, y un
  // «contraseña incorrecta» se perdía por el camino sin que nadie lo llegara a ver.
  const dumpProfiles = (extra = {}) => { writeState(); writeJson(profilesFile, { v: 1, at: Date.now(), req: null, current: mgr.currentId(), profiles: mgr.summary(), ...extra }) }

  console.log(`dotrino-vault · datos en ${dir} · proxy ${proxyUrl}`)
  for (const p of mgr.summary()) {
    console.log(`perfil ${p.current ? '*' : ' '} ${p.name || '(sin nombre)'} · ${p.id} · ${p.fingerprint}${p.protected ? (p.locked ? ' · 🔒 bloqueado' : ' · 🔓 desbloqueado') : ''}`)
  }

  /**
   * Perfil destino de una petición de la CLI (o el activo si no lo dice), con su CANDADO.
   *
   * EL CANDADO ES DE ESTA CONSOLA. Un perfil con contraseña y bloqueado no se puede ver ni
   * tocar desde la máquina de la bóveda —ni la lista de aparatos, ni las variables, ni tus
   * datos, ni emparejar o quitar nada— hasta que alguien teclee la contraseña
   * (`dotrino-vault unlock`). Lo que NO cambia es el servicio: los aparatos ya emparejados
   * siguen firmando, leyendo y guardando, porque la bóveda es de ellos tanto como de esta
   * pantalla. Lo que se protege es la consola, que es donde se administra y donde se mira.
   */
  const resolveTarget = (req) => {
    try {
      const id = req?.profile ? mgr.resolve(req.profile) : mgr.currentId()
      return { id, vault: mgr.get(id), locked: mgr.profiles.isLocked(id) }
    } catch (e) { console.error('[vault] invalid profile in the request:', e.message); return null }
  }
  /** La bóveda destino, o `null` si el perfil está bloqueado (la petición no se atiende). */
  const targetOf = (req) => {
    const t = resolveTarget(req)
    if (!t) return null
    if (t.locked) { console.error('[vault] profile %s is locked: request refused (unlock it to use this console)', t.id); return null }
    return t.vault
  }

  // --- SIGUSR1: iniciar emparejamiento ---
  const pairFile = path.join(dir, 'pair.json')
  let pendingApproval = false // lo pidió `pair --approval`; se aplica al aprobar
  const pairReqFile = path.join(dir, 'pair-request.json')
  async function handlePairingRequest () {
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
      const locked = resolveTarget(pairReq)
      if (locked?.locked) {
        // Se responde por el MISMO archivo que espera quien pidió el QR: si no, se queda
        // mirando una pantalla vacía hasta que se agote el tiempo, sin saber por qué.
        writeJson(pairFile, { v: 2, at: Date.now(), profile: locked.id, locked: true })
        return console.error('[vault] profile %s is locked: pairing refused', locked.id)
      }
      const vault = targetOf(pairReq)
      if (!vault) return
      const profileId = pairReq?.profile ? mgr.resolve(pairReq.profile) : mgr.currentId()
      const isService = typeof pairReq?.service === 'string' && pairReq.service
      // PERMISOS, no tipos (2026-08-22): el cert lleva lo que pidió `pair --scope`, y si
      // no pidió nada, el juego de siempre. `--service <ns>` sigue siendo el atajo de
      // `vault:secrets:<ns>`. Se valida aquí porque es la maestra la que firma: nada
      // que no esté en esta lista entra en un cert, y `vault:admin` / `vault:approve` nunca
      // por este camino (se conceden a mano con `caps`).
      const ALLOWED = (x) => x === 'vault:sign' || x === 'vault:read' || x === 'vault:store' || /^vault:secrets:[a-z0-9-]{1,32}$/.test(x)
      const asked = Array.isArray(pairReq?.scope) ? pairReq.scope.filter((x) => typeof x === 'string') : null
      if (asked && asked.some((x) => !ALLOWED(x))) {
        writeJson(pairFile, { v: 2, at: Date.now(), error: 'scope not allowed: ' + asked.filter((x) => !ALLOWED(x)).join(',') })
        return console.error('[vault] pairing refused: scope not allowed (%s)', asked.join(','))
      }
      const scope = asked?.length
        ? [...new Set(asked)]
        : isService ? ['vault:secrets:' + pairReq.service] : ['vault:sign', 'vault:read', 'vault:store']
      // La etiqueta por defecto de un servicio es su ns a secas: la lista ya marca [servicio «ns»],
      // y el prefijo «service:» confundía (el cajón se llama claude, no service:claude).
      const label = pairReq?.label || (isService ? pairReq.service : 'cli')
      // `pair --approval`: el aparato que entre por esta invitación pedirá el visto bueno del
      // teléfono cada vez que reciba claves privadas (se aplica al aprobarlo, abajo).
      pendingApproval = !!pairReq?.approval
      // `profile`/`profileName`: la CUENTA del vault a la que entra el dispositivo.
      // Con varias bóvedas en el mismo daemon, el QR sale de UNA y quien empareja
      // tiene que verlo (lo muestran la TUI y `dotrino-vault pair`). El nombre viaja
      // TAMBIÉN dentro del QR (`acct`) para que el dispositivo pueda anunciar qué va
      // a pasar antes de hacerlo (V9 de docs/vinculacion-de-cuentas.md).
      const profileName = mgr.profiles.get(profileId)?.name || ''
      // MODO (V9): lo decide la bóveda y viaja en el QR para que el aparato pueda decir
      // qué va a pasar antes de hacerlo.
      //   · `join`  → el dispositivo entra a esta cuenta de la bóveda.
      //   · `adopt` → la bóveda se queda con la cuenta que trae el aparato (camino A). El
      //               perfil de esta bóveda tiene que haber nacido para eso (`--adopt`
      //               crea uno vacío), o no habría dónde meterla.
      const mode = pairReq?.mode === 'adopt' ? 'adopt' : 'join'
      const { qr, expiresInMs } = await vault.startPairing({ scope, label, ttlMs: DEVICE_TTL_MS, mode, account: profileName })
      writeJson(pairFile, { v: 2, at: Date.now(), qr, expiresAt: Date.now() + expiresInMs, profile: profileId, profileName })
      // El token es un secreto efímero: no debe quedar en disco más allá de su
      // vida. Se borra al VENCER (aquí) y al APROBARSE (abajo, consumido).
      const tok = qr.token
      setTimeout(() => {
        const cur = readJsonSafe(pairFile)
        if (cur?.qr?.token === tok) rm(pairFile)
      }, expiresInMs + 1000).unref?.()
      console.log('[vault] pairing started (valid for %d min)', expiresInMs / 60000)
    } catch (e) {
      console.error('[vault] no se pudo iniciar emparejamiento:', e.message)
    }
  }

  // --- SIGUSR2: approve / reject / revoke / secretos / perfiles + volcados ---
  const devFile = path.join(dir, 'devices.json')
  const approveReqFile = path.join(dir, 'approve-request.json')
  const approveFile = path.join(dir, 'approve.json')
  const rejectReqFile = path.join(dir, 'reject-request.json')
  const revokeReqFile = path.join(dir, 'revoke-request.json')
  const secretReqFile = path.join(dir, 'secret-request.json')
  const secretsListFile = path.join(dir, 'secrets-list.json')
  /**
   * Por qué falló la última orden de variables. La consola pide el cambio y el volcado
   * por señales distintas, así que el motivo no cabe en la respuesta: se guarda aquí y
   * viaja en el volcado siguiente. Sin esto, una contraseña equivocada se leía como
   * «El daemon no aplicó el cambio», que no dice qué hacer.
   */
  let lastSecretError = null
  /**
   * El VALOR que se acaba de destapar, esperando al volcado siguiente (mismo camino que
   * `lastSecretError`: la orden y el volcado son señales distintas). Vive en memoria un
   * instante y se va con el volcado — quien lo lee borra el archivo enseguida.
   */
  let lastSecretValue = null
  /** Y las versiones anteriores que se acaban de pedir. Mismo camino, mismo volcado. */
  let lastSecretHistory = null
  const profileReqFile = path.join(dir, 'profile-request.json')
  const dumpReqFile = path.join(dir, 'dump-request.json')
  const meReqFile = path.join(dir, 'me-request.json')
  const meFile = path.join(dir, 'me.json')

  /** Resumen de la foto de perfil: qué es y cuánto pesa, nunca los bytes. */
  function avatarInfo (avatar) {
    if (typeof avatar !== 'string' || !avatar) return null
    const m = /^data:([^;,]+)?(?:;base64)?,(.*)$/s.exec(avatar)
    if (!m) return { type: null, bytes: avatar.length }
    return { type: m[1] || 'desconocido', bytes: Math.floor(m[2].length * 3 / 4) }
  }

  /**
   * Órdenes de perfil (crear/renombrar/borrar/activar) y del candado
   * (unlock/lock/password). La contraseña llega en un archivo 0600 dentro del dir
   * 0700 del vault y se BORRA al consumirla — mismo camino que ya usan los
   * secretos, y así nunca pasa por `ps` ni por el historial de la shell.
   */
  /**
   * Vuelve a cerrar la copia maestra de los secretos con otra llave. Se llama al poner
   * o quitar la contraseña del perfil: los sobres de las variables NO se tocan (siguen
   * sellados a la llave de cada aparato), solo cambia con qué se abre el llavero de
   * administración. Sin esto, cambiar la contraseña dejaría los secretos ilegibles.
   */
  async function rekey (id, vieja, nueva) {
    const v = mgr.get(id)
    if (!v?.rekeySecrets) return
    const r = await v.rekeySecrets(vieja, nueva)
    if (r?.rekeyed) console.log('[vault] secrets master re-sealed (%d drawer(s))', r.drawers)
  }

  async function handleProfileRequest (req) {
    const ref = () => mgr.resolve(req.profile || mgr.currentId())
    switch (req.op) {
      case 'list': return {} // el volcado de perfiles ya se hace abajo
      // `id`: quien la crea necesita saber CUÁL quedó, no adivinar por nombre (dos
      // cuentas pueden llamarse igual). Lo usa «emparejar en una cuenta nueva».
      case 'add': { const p = await mgr.add(req.name, { adopt: !!req.adopt }); return { done: `perfil creado: ${p.name || p.id}`, id: p.id, adopt: !!req.adopt } }
      case 'rm': { const r = await mgr.remove(req.profile); return { done: `perfil borrado: ${r.name || r.id}` } }
      case 'rename': { const p = mgr.profiles.rename(ref(), req.name); return { done: `perfil renombrado: ${p.name}` } }
      case 'use': { const p = mgr.profiles.setCurrent(ref()); return { done: `perfil activo: ${p.name || p.id}` } }
      // ABRIR LA BÓVEDA SALDA LO QUE SE DEBE. Un aparato que entró después de escrita
      // una variable no puede abrirla —envolverle su llave exige abrir la CEK, y eso
      // pide la frase—, así que se queda en deuda y se ve en la consola y en la TUI.
      // Este es el único momento en que la frase está delante, así que es aquí donde se
      // paga; el dueño no tiene que acordarse de un comando aparte.
      case 'unlock': {
        const id = ref()
        await mgr.profiles.unlock(id, req.password)
        let note = ''
        try {
          const ak = await mgr.profiles.adminKey(id, req.password)
          // REHACER el llavero, no solo saldar: con la frase delante se puede dejar cada
          // cajón envuelto para exactamente quien dice el acta — creando lo que falta,
          // reemplazando lo que alguien metiera mal y quitando lo que sobre.
          const r = await mgr.get(id)?.resealAll?.(ak)
          if (r?.wrapped) console.log('[vault] keyring rebuilt on unlock: %d wrap(s) in %d drawer(s)%s',
            r.wrapped, r.drawers, r.dropped ? `, ${r.dropped} stale one(s) dropped` : '')
          if (r?.dropped) note = ` · llavero al día (${r.dropped} envoltura(s) de más retirada(s))`
          else if (r?.wrapped) note = ' · llavero al día'
        } catch (e) { console.error('[vault] could not rebuild the keyring on unlock:', e.message) }
        return { done: 'perfil desbloqueado' + note }
      }
      case 'lock': { mgr.profiles.lock(ref()); return { done: 'perfil bloqueado' } }
      // PONER contraseña: los secretos pasan de abrirse con la llave de la máquina a
      // abrirse con la frase. Hay que volver a cerrar la copia maestra con la nueva, o
      // quedarían ilegibles. Si el perfil YA tenía contraseña, hace falta la vieja para
      // poder abrirla: por eso el camino normal para cambiarla es quitarla y ponerla.
      case 'password-set': {
        const id = ref()
        const tenia = !!mgr.profiles.get(id)?.protected
        if (tenia && !req.current) throw new Error('this profile already has a password: remove it first (`profile password --rm`) and then set the new one')
        const vieja = tenia ? await mgr.profiles.adminKey(id, req.current) : null
        await mgr.profiles.setPassword(id, req.password)
        const nueva = await mgr.profiles.adminKey(id, req.password)
        await rekey(id, vieja, nueva)
        return { done: 'contraseña guardada' }
      }
      // QUITARLA: al revés. Se abre la copia maestra con la frase y se vuelve a cerrar
      // con la llave de la máquina, que es la protección de siempre — el disco sigue
      // cifrado, pero su material vive en ese mismo disco.
      case 'password-rm': {
        const id = ref()
        if (!req.password) throw new Error('removing the password needs the current one: the secrets must be re-sealed before it goes')
        const vieja = await mgr.profiles.adminKey(id, req.password)
        await rekey(id, vieja, null)
        mgr.profiles.removePassword(id)
        return { done: 'contraseña quitada · los secretos ahora se abren con la llave de esta máquina' }
      }
      default: throw new Error('unknown profile operation: ' + req.op)
    }
  }

  async function handleRequests () {
    try {
      const appr = readJsonSafe(approveReqFile)
      if (appr?.code) {
        rm(approveReqFile)
        // EL RESULTADO SE CONTESTA, no solo se anota en el log del servicio. Un código
        // equivocado NO emite certificado (lo corta `enroll.js`), pero eso se quedaba en
        // esta consola: quien aprobaba desde la TUI leía «Dispositivo aprobado», el
        // pendiente desaparecía de la pantalla y el aparato seguía esperando al otro lado
        // sin que nadie pudiera reintentar.
        const answer = (extra) => writeJson(approveFile, { v: 1, at: Date.now(), req: appr.id || null, ...extra })
        try {
          const vault = targetOf(appr)
          if (!vault) throw Object.assign(new Error('profile locked'), { code: 'PROFILE_LOCKED' })
          const r = await vault.approveDevice(appr.code); rm(pendingEnrollFile); rm(pairFile)
          if (pendingApproval && r?.cert?.sub) { try { await vault.setApproval(r.cert.sub, true); console.log('[vault] the new device will need approval on every key request') } catch (e) { console.error('[vault] could not flag approval: %s', e.message) } }
          pendingApproval = false
          console.log('[vault] aprobado %s', r.deviceId)
          answer({ ok: true, deviceId: r.deviceId || null })
        } catch (e) {
          console.error('[vault] approval failed:', e.message)
          answer({ ok: false, error: e.message, code: e.code || 'APPROVE_FAILED' })
        }
      }
      const rej = readJsonSafe(rejectReqFile)
      if (rej?.deviceId) {
        try { targetOf(rej)?.rejectDevice(rej.deviceId); rm(pendingEnrollFile) } catch (_) {}
        rm(rejectReqFile)
      }
      // Cambio de permisos de un miembro del acta (`dotrino-vault caps`).
      // Renombrar un dispositivo (`dotrino-vault label <ID> <nombre>`).
      const labelReq = readJsonSafe(path.join(dir, 'label-request.json'))
      if (labelReq?.pub && typeof labelReq.label === 'string') {
        rm(path.join(dir, 'label-request.json'))
        try {
          await targetOf(labelReq)?.setLabel(labelReq.pub, labelReq.label)
          console.log('[vault] device renamed: %s', labelReq.label || '(no name)')
        } catch (e) { console.error('[vault] could not rename the device:', e.message) }
      }
      const capsReq = readJsonSafe(path.join(dir, 'caps-request.json'))
      if (capsReq?.pub && Array.isArray(capsReq.caps)) {
        rm(path.join(dir, 'caps-request.json'))
        try {
          await targetOf(capsReq)?.setCaps(capsReq.pub, capsReq.caps)
          console.log('[vault] permissions updated: %s', capsReq.caps.join(', ') || '(ninguno)')
        } catch (e) { console.error('[vault] could not change permissions:', e.message) }
      }
      // Quitar un dispositivo: se pide por `sub` (la llave del aparato). `nonce` sigue
      // aceptado para una consola vieja, pero retira UN certificado, no el aparato.
      const req = readJsonSafe(revokeReqFile)
      if (req?.sub || req?.nonce) {
        try {
          await targetOf(req)?.revokeDevice(req.sub ? { sub: req.sub } : { nonce: req.nonce })
          console.log(req.sub ? '[vault] device removed' : '[vault] revoked nonce=%s', req.nonce || '')
        } catch (e) { console.error('[vault] revocation failed:', e.message) }
        rm(revokeReqFile)
      }
      // Secretos: `secret set/rm` (por SCOPE) y `secret device set/rm` (por APARATO),
      // del CLI o de la TUI. El archivo con el valor vive un instante en el mismo dir
      // 0700 del vault y se borra al consumir.
      const sec = readJsonSafe(secretReqFile)
      if (sec?.op) {
        rm(secretReqFile) // puede llevar la contraseña: fuera del disco cuanto antes
        lastSecretError = null
        try {
          const vault = targetOf(sec)
          // Carga en GRUPO (`secret set ns K=v K2=v2`, `secret import`): todas las
          // variables entran de una vez y sale UN solo aviso de cambio, para que el
          // servicio no se reinicie a media carga y arranque con la mitad puesta.
          // La CONTRASEÑA, si vino, se convierte en la llave que abre la copia de
          // RECUPERACIÓN, y no se guarda en ningún sitio: se usa y se suelta. Desde v5
          // solo la piden las operaciones que LEEN —ver un valor, cambiar su visibilidad,
          // convertir el archivo, rotar re-cifrando—: escribir no (§8.1). Sin ella se cae
          // a la llave de la máquina, que es la protección de antes de esto (y el vault lo
          // avisa al arrancar).
          const ak = sec.password ? await mgr.profiles.adminKey(sec.profile ? mgr.resolve(sec.profile) : mgr.currentId(), sec.password) : undefined
          if (sec.op === 'migrate') {
            // Sin lista a mano: la pone el vault, y es la MISMA que usa cualquier
            // escritura (servicios del cajón + aparatos que administran). Con una lista
            // propia aquí, lo convertido quedaba sellado solo a los servicios y el dueño
            // no podía ver desde su consola nada de lo que ya tenía.
            const r = await vault.migrateSecrets(null, ak)
            if (!r.migrated) console.log('[vault] nothing to migrate: %s', r.reason)
            else {
              console.log('[vault] secrets SEALED (v%d -> v5). Backup left at secrets.json.v%d.bak', r.from, r.from)
              for (const [owner, sin] of Object.entries(r.sinLlave || {})) {
                console.log('[vault] WARNING %s: %d member(s) without an encryption key will NOT read their variables', owner, sin.length)
              }
            }
          } else if (sec.op === 'batch') {
            const changed = sec.pub
              ? await vault.applyDeviceSecrets(sec.pub, sec.items, { by: null })
              : await vault.applySecrets(sec.ns, sec.items, { by: null })
            console.log('[vault] %d secret(s) applied in one go: %s', changed.length, sec.pub ? 'device' : sec.ns)
          } else if (sec.op === 'set') { await vault.setSecret(sec.ns, sec.key, sec.value, sec.public); console.log('[vault] secret saved: %s/%s', sec.ns, sec.key) }
          else if (sec.op === 'rm') { await vault.deleteSecret(sec.ns, sec.key); console.log('[vault] secret deleted: %s/%s', sec.ns, sec.key) }
          else if (sec.op === 'approval') { const r = await vault.setApproval(sec.pub, !!sec.approval); console.log('[vault] device %s: approval %s', sec.id || '?', r.approval ? 'REQUIRED on every key request' : 'off') }
          else if (sec.op === 'dev-set') { await vault.setDeviceSecret(sec.pub, sec.key, sec.value, sec.public); console.log('[vault] device secret saved: %s', sec.key) }
          else if (sec.op === 'dev-rm') { await vault.deleteDeviceSecret(sec.pub, sec.key); console.log('[vault] device secret deleted: %s', sec.key) }
          // Saldar lo que quedó a deber: heredarle a un aparato nuevo lo ya guardado y
          // rotar de verdad el cajón del que salió alguien. Las dos cosas abren, así que
          // van con la frase — y por eso se hacen aquí y no al escribir.
          else if (sec.op === 'settle') {
            const r = await vault.settleSecretDebts(ak)
            const n = Object.keys(r).length
            console.log(n ? `[vault] ${n} pending drawer(s) settled` : '[vault] nothing pending')
          }
          // Ver el valor de una privada: lo único que la frase guarda (§8.3).
          else if (sec.op === 'reveal') {
            const value = await vault.revealSecret(sec.owner, sec.key, ak)
            lastSecretValue = { owner: sec.owner, key: sec.key, value }
          }
          // Qué versiones anteriores hay (sin valores: son sobres).
          else if (sec.op === 'history') {
            lastSecretHistory = { owner: sec.owner || null, key: sec.key || null, items: vault.secretHistory(sec.owner || null, sec.key || null) }
          }
          // REVERTIR: abrir la versión vieja (frase) y volver a guardarla (nada).
          else if (sec.op === 'revert') {
            const ok = await vault.revertSecret(sec.owner, sec.key, sec.ts, { adminKey: ak })
            if (!ok) throw new Error('that version is not in the history any more')
            console.log('[vault] secret reverted: %s/%s', sec.owner, sec.key)
          }
          // Visibilidad: si el valor puede salir hacia la consola remota. No toca el valor.
          else if (sec.op === 'vis') { await vault.setSecretVisibility(sec.ns, sec.key, sec.public, ak); console.log('[vault] secret visibility: %s/%s → %s', sec.ns, sec.key, sec.public ? 'public' : 'private') }
          else if (sec.op === 'dev-vis') { await vault.setDeviceSecretVisibility(sec.pub, sec.key, sec.public, ak); console.log('[vault] device secret visibility: %s → %s', sec.key, sec.public ? 'public' : 'private') }
        } catch (e) {
          lastSecretError = {
            error: e.message,
            code: e.code || (/wrong password/i.test(e.message) ? 'WRONG_PASSWORD' : 'SECRET_FAILED')
          }
          console.error('[vault] secret failed:', e.message)
        }
      }
      // Perfiles / candado.
      const preq = readJsonSafe(profileReqFile)
      if (preq?.op) {
        rm(profileReqFile) // lleva la contraseña: fuera del disco cuanto antes
        // `req`: el id de la petición viaja de vuelta en el volcado. Sin él, quien
        // espera podía quedarse con un volcado anterior —el daemon los escribe también
        // por su cuenta— y dar por contestado lo que aún no se había hecho.
        let extra = { req: preq.id || null }
        try { extra = { ...extra, ...(await handleProfileRequest(preq)) } }
        // `code`: la TUI es bilingüe y traduce por código (un freno como el D12 tiene
        // que leerse en el idioma de quien lo lee, no en el del daemon).
        catch (e) {
          // `waitSec`/`tries` viajan con el error: quien lo enseña necesita el dato, no
          // solo el motivo («espera 32 s» y «van 9 intentos» son lo que cambia la conducta).
          extra = { req: preq.id || null, error: e.message, ...(e.code ? { code: e.code } : {}), ...(e.waitSec ? { waitSec: e.waitSec } : {}), ...(e.tries ? { tries: e.tries } : {}) }
          console.error('[vault] profile: %s', e.message)
        }
        dumpProfiles(extra)
      } else {
        // NADIE PREGUNTÓ: se refresca el estado, pero NO se pisa `profiles-list.json`.
        // Ese archivo es la RESPUESTA a una petición, y el daemon repasa su carpeta cada
        // dos segundos: al volcarlo también sin que nadie lo pidiera, un repaso que caía
        // entre la respuesta y quien la esperaba se la llevaba por delante. Eso es lo que
        // hacía que un `unlock` correcto contestara «sigue cerrada» y que un «contraseña
        // incorrecta» se perdiera sin llegar a verse. Quien lee esta lista —la TUI y el
        // CLI— siempre pide antes, así que no se queda sin ella.
        writeState()
      }
      // Volcados que lee la CLI (`devices`, `members`, `secret list`) y la TUI. A QUÉ
      // perfil miran lo dice dump-request.json; sin él, al activo.
      //
      // SOLO SI ALGUIEN LOS PIDIÓ. Estos archivos son la RESPUESTA a una petición, igual
      // que `profiles-list.json` (ver arriba), y el daemon pasa por aquí cada dos segundos
      // —y otra vez, en el acto, si algo llegó mientras atendía—. Volcarlos también sin que
      // nadie preguntara se llevaba por delante la respuesta recién escrita: quien esperaba
      // veía un volcado con `req: null` en vez del suyo, seguía esperando y a los seis
      // segundos se rendía. Eso era la TUI colgada en «Cargando dispositivos…» y luego «el
      // daemon no responde» — con el daemon sano y contestando en milisegundos.
      // NO SE BORRA LO QUE NO SE PUDO LEER. `readJsonSafe` devuelve null tanto si el
      // archivo no está como si llegó a medias (`fs.watch` avisa al crearlo, no al
      // terminar de escribirlo), y borrarlo en ese segundo caso destruía la petición: el
      // que la había pedido esperaba seis segundos y leía «el daemon no respondió», con el
      // daemon sano y contestando lo demás. Si no parsea se deja donde está y lo recoge el
      // repaso de 2 s, que es la misma regla que ya tenía la petición de emparejamiento.
      const dumpReq = readJsonSafe(dumpReqFile)
      if (dumpReq || !fs.existsSync(dumpReqFile)) rm(dumpReqFile)
      const meReq = readJsonSafe(meReqFile)
      if (!dumpReq && !meReq) return
      const t = resolveTarget(dumpReq || meReq || appr || rej || req || sec || {}) || { id: mgr.currentId(), vault: mgr.current(), locked: false }
      // El id de la petición vuelve en cada volcado, para que quien espera sepa que le
      // contestan a ÉL y no lea el volcado de la vuelta anterior (ver `waitFor`).
      const reqId = dumpReq?.id || null
      if (t.locked) {
        // BLOQUEADO: se contesta que lo está, y nada más. Los volcados se escriben igual
        // (quien pregunta espera una respuesta, no un plantón) pero VACÍOS: ni aparatos, ni
        // nombres de variables, ni acta. Antes el candado no tapaba ninguna de las tres.
        const closed = { v: 1, at: Date.now(), req: reqId, profile: t.id, locked: true }
        if (dumpReq) {
          writeJson(secretsListFile, { ...closed, ns: {}, dev: [] })
          writeJson(devFile, { ...closed, issued: [], revoked: [] })
          writeJson(path.join(dir, 'acta.json'), { ...closed, members: [] })
        }
        rm(meReqFile)
        if (meReq) writeJson(meFile, { ...closed, req: meReq.id || null, me: null })
        return
      }
      if (dumpReq) {
        // Los DOS cajones: `ns` (por scope, que comparten todos los aparatos del perfil) y
        // `dev` (las propias de cada aparato). Con el VALOR de las públicas —que es lo que
        // pública significa— y sin el de las privadas, que no salen del proceso.
        //
        // Ese valor queda escrito en claro en este archivo (0600, y quien lo lee lo borra
        // en cuanto lo tiene). Es material que su dueño marcó como mostrable, y aquí ya
        // viaja a un navegador; lo que NO puede pasar es que se quede en el disco esperando
        // a que alguien copie la carpeta, porque eso sí burlaría el cifrado en reposo.
        writeJson(secretsListFile, {
          v: 2, at: Date.now(), req: reqId, profile: t.id,
          ns: t.vault.listSecrets(),
          dev: await t.vault.listDeviceSecrets(),
          // Lo que quedó a deber un sellado. Va en el volcado porque si no se ve, no se
          // salda: son cajones cuyos miembros NO están leyendo sus variables.
          pending: await t.vault.secretDebts(),
          // Y quién NO puede abrir lo suyo. Es lo mismo visto desde el aparato, que es
          // como lo mira quien administra: «este servicio está en el acta y aun así no
          // arranca». Sin esto solo se veía en el log del propio servicio.
          incomplete: await t.vault.incompleteMembers(),
          ...(lastSecretError ? { secretError: lastSecretError } : {}),
          ...(lastSecretValue ? { revealed: lastSecretValue } : {}),
          ...(lastSecretHistory ? { history: lastSecretHistory } : {})
        })
        lastSecretError = null
        lastSecretValue = null
        lastSecretHistory = null
        writeJson(devFile, { v: 1, at: Date.now(), req: reqId, profile: t.id, ...(await t.vault.listDevices()) })
        // Acta del perfil: quién es del perfil y qué puede hacer cada uno (`members`/`caps`).
        try { writeJson(path.join(dir, 'acta.json'), { v: 1, at: Date.now(), req: reqId, profile: t.id, ...(await t.vault.profileMembers()) }) } catch (_) {}
      }

      // PERFIL del usuario (apodo, foto, datos) tal como lo tiene la bóveda: `dotrino-vault me`.
      // Solo se vuelca cuando se PIDE, no en cada señal: es contenido del usuario y no tiene
      // por qué quedar escrito en un archivo suelto cada vez que alguien mira los miembros.
      // La FOTO no entra en el volcado (son hasta ~90 KB de data-URI que nadie va a leer en
      // una terminal): solo se dice que la hay, de qué tipo y cuánto pesa.
      if (meReq) {
        rm(meReqFile)
        try {
          const tm = resolveTarget(meReq) || { id: mgr.currentId(), vault: mgr.current() }
          const { me } = tm.vault.threads.methods.profileGet()
          const { avatar, ...rest } = me || {}
          writeJson(meFile, { v: 1, at: Date.now(), req: meReq.id || null, profile: tm.id, me: me ? { ...rest, avatar: avatarInfo(avatar) } : null })
        } catch (e) { console.error('[vault] could not dump the profile:', e.message) }
      }
    } catch (e) {
      console.error('[vault] error handling a control signal:', e.message)
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
  const SWEEP_MS = 2000
  let serving = false
  let anotherRound = false
  async function serve () {
    // Una a la vez (las peticiones se consumen y se borran), pero lo que llegue mientras
    // tanto NO se pierde: se anota y se da otra vuelta al terminar. Antes se descartaba,
    // y la petición se quedaba esperando al repaso de 2 s — tiempo de sobra para que
    // quien pidió escribiera la siguiente encima.
    if (serving) { anotherRound = true; return }
    serving = true
    try {
      // OJO: `fs.watch` avisa al CREAR el archivo, antes de que el CLI termine de
      // escribirlo. Si se lee a medias, el JSON no parsea y la petición se pierde con
      // sus datos — y el emparejamiento salía como si fuera de un dispositivo normal,
      // sin el `--service`, emitiendo un cert con el scope equivocado. Así que solo se
      // atiende cuando el archivo YA parsea; si no, lo recoge el repaso de 2 s.
      if (readJsonSafe(pairReqFile)) await handlePairingRequest()
      await handleRequests()
    } catch (e) { console.error('[vault] error serving a request:', e.message) }
    finally { serving = false }
    if (anotherRound) { anotherRound = false; await serve() }
  }

  try {
    fs.watch(dir, (_ev, file) => { if (!file || /-request\.json$/.test(file)) serve() })
  } catch (e) {
    console.error('[vault] could not watch %s (%s); will be served by polling only', dir, e.message)
  }
  const sweep = setInterval(serve, SWEEP_MS)
  sweep.unref?.()

  // POSIX: la señal sigue valiendo como atajo inmediato. En Windows no existe y no pasa nada.
  // Van por `atender()` y NO llaman directo: si no, la señal y el vigilante corren a la
  // vez, la primera consume la petición y la segunda la lee vacía — y un `pair --service`
  // acababa emitiendo un cert de dispositivo normal, con el scope equivocado.
  if (process.platform !== 'win32') {
    process.on('SIGUSR1', () => { serve() })
    process.on('SIGUSR2', () => { serve() })
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
