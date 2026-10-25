/**
 * LA BÓVEDA EN LAMBDA SE ACTUALIZA SOLA (CONVENCIONES §15), con el cargador de `code.mjs`.
 *
 * Una vez al día, durante una sesión, mira la última release. Si es más nueva que lo que
 * corre y que lo ya apuntado, baja su zip, lo VERIFICA contra la atestación de sigstore de la
 * release, lo deja en `code/` de su bucket y apunta `code/current.json`. Desde el siguiente
 * arranque en frío corre esa versión. Nada de esto toca la pila.
 *
 * Las mismas reglas que el binario (`src/daemon.js`, `checkRelease`):
 *
 *   · se actualiza sola; pedir aprobación es un ajuste (`settings.json`, `updateApproval`);
 *   · con el ajuste encendido se pide UNA vez por versión a quien tenga `aprueba`, y si nadie
 *     aprueba en el acta se actualiza igual;
 *   · si el ajuste o lo ya preguntado no se pueden leer, no se actualiza y se dice;
 *   · lo que no se puede verificar no se instala;
 *   · «no se pudo mirar» se dice, y no es «al día».
 *
 * Lo que es distinto, y se dice: el pedido de aprobación vive en la memoria de la sesión, así
 * que dura lo que dura ella (como mucho los 15 min de la función), no un día. Sin respuesta
 * para entonces, cuenta como vencido y esa versión no se vuelve a pedir.
 *
 * Y cuando la versión nueva arranca por primera vez, ELLA avisa a quien aprueba
 * (`announceIfNew`): es la que puede decir con verdad que ya corre.
 */
import fs from 'node:fs'
import { createHash } from 'node:crypto'
import { readCurrent, writeCurrent } from './code.mjs'

export const CHECKED = 'checked.json'
/** El asset de la release que le toca a la Lambda (el de la demo no va en la release). */
export const assetName = (version) => `dotrino-vault-lambda-${version}.zip`

const missing = (e) => e.code === 'ENOENT' || e.name === 'NoSuchKey'

async function readChecked (store) {
  try { return JSON.parse((await store.get(CHECKED)).body.toString('utf8')) } catch (e) {
    if (missing(e)) return null
    // Un archivo de control roto no puede dejar a la bóveda sin mirar nunca: se mira otra vez.
    if (e instanceof SyntaxError) return null
    throw e
  }
}

/**
 * Una pasada. Devuelve lo que hizo (`{ did, ... }`) para el log y las pruebas.
 *
 * @param {object} o
 * @param {object} o.store        el almacén de `code/` del bucket
 * @param {string} o.dir          el directorio del perfil (donde viven `settings.json` y
 *                                `update-asked.json`, que se reflejan en el bucket)
 * @param {string} o.myVersion    la versión que corre
 * @param {object|null} o.vault   la bóveda en marcha (`approvers`, `askUpdateApproval`); `null`
 *                                en la réplica, que no tiene acta propia que mirar
 * @param {number} o.deadline     hasta cuándo puede esperar una aprobación
 * @param {object} o.deps         `{ latestRelease, isNewer, fetchVerified, readSettings,
 *                                readAsked, writeAsked, clearAsked, shouldAsk, firstYes, checkEveryMs, repo }`
 */
export async function updateCode ({ store, dir, myVersion, vault = null, deadline, log = () => {}, now = Date.now, deps }) {
  const { latestRelease, isNewer, fetchVerified, readSettings, readAsked, writeAsked, clearAsked, shouldAsk, firstYes, checkEveryMs, repo } = deps
  const checked = await readChecked(store)
  if (checked?.at && now() - checked.at < checkEveryMs) return { did: 'recently-checked' }

  let r
  try { r = await latestRelease() } catch (e) { r = { ok: false, reason: e?.message || String(e) } }
  if (!r.ok) {
    log(`[vault-lambda] could not check for a new version: ${r.reason} · trying again in the next session`)
    return { did: 'check-failed', reason: r.reason }
  }
  // «YA SE MIRÓ HOY» SOLO CUANDO LA PASADA TERMINÓ (al día, instalada o sin aprobar). Si se
  // apuntara antes, un fallo al bajar o al verificar dejaría a la bóveda un día entero sin
  // volver a intentarlo, y sin decirlo (pasó en la primera prueba en AWS, 2026-10-25).
  const done = async (result) => {
    await store.put(CHECKED, Buffer.from(JSON.stringify({ at: now(), latest: r.version })))
    return result
  }

  const cur = await readCurrent(store)
  const running = cur && isNewer(cur.version, myVersion) ? cur.version : myVersion
  if (!isNewer(r.version, running)) {
    log(`[vault-lambda] up to date (${running})`)
    return done({ did: 'up-to-date', version: running })
  }

  let askPermission
  try { askPermission = readSettings(dir).updateApproval } catch (e) {
    log(`[vault-lambda] version ${r.version} is out, but the settings could not be read (${e?.message || e}) · not updating`)
    return { did: 'settings-unreadable' }
  }
  if (askPermission && vault) {
    let who
    try { who = await vault.approvers() } catch (e) {
      log(`[vault-lambda] version ${r.version} is out, but the approvers could not be read (${e?.message || e}) · not updating`)
      return { did: 'approvers-unreadable' }
    }
    if (who.length) {
      let asked
      try { asked = readAsked(dir) } catch (e) {
        log(`[vault-lambda] version ${r.version} is out, but what was already asked could not be read (${e?.message || e}) · not updating`)
        return { did: 'asked-unreadable' }
      }
      if (!shouldAsk(asked, r.version, isNewer)) {
        log(`[vault-lambda] version ${r.version} is out (this one runs ${running}) · approval for ${asked.version} was asked and not given (${asked.result}) · not asking again until a newer version`)
        return done({ did: 'not-approved', version: r.version })
      }
      const askedAt = now()
      writeAsked(dir, { version: r.version, askedAt, result: 'pending' })
      log(`[vault-lambda] version ${r.version} is out (this one runs ${running}) · asking ${who.length} approver(s), once, while this session lasts`)
      const ask = vault.askUpdateApproval({ version: r.version })
      const timer = setTimeout(() => ask.withdraw(), Math.max(0, deadline - now()))
      let yes
      try { yes = await firstYes([ask]) } finally { clearTimeout(timer) }
      if (!yes) {
        // Sin respuesta antes de que acabe la sesión el pedido muere con ella: es un vencimiento.
        const result = now() >= deadline ? 'expired' : 'denied'
        writeAsked(dir, { version: r.version, askedAt, result })
        log(`[vault-lambda] update to ${r.version}: not approved (${result}) · it will not ask again for this version`)
        return done({ did: 'not-approved', version: r.version })
      }
    }
  }

  const asset = (r.assets || []).find((a) => a.name === assetName(r.version))
  if (!asset) {
    log(`[vault-lambda] version ${r.version} is out, but its release has no ${assetName(r.version)} · not updating`)
    return { did: 'no-asset', version: r.version }
  }
  const v = await fetchVerified(asset, { repo, product: 'dotrino-vault-lambda', version: myVersion })
  if (!v.ok) {
    log(`[vault-lambda] update to ${r.version} NOT installed: ${v.reason}`)
    return { did: 'not-verified', version: r.version, reason: v.reason }
  }
  const body = fs.readFileSync(v.file)
  const sha256 = createHash('sha256').update(body).digest('hex')
  const key = `dotrino-vault-lambda-${sha256}.zip`
  await store.put(key, body)
  await writeCurrent(store, { version: r.version, sha256, key, from: running, at: now(), announced: false })
  try { clearAsked(dir) } catch (_) {}
  log(`[vault-lambda] update: ${r.version} verified and in place · it runs from the next cold start`)
  return done({ did: 'installed', version: r.version, key })
}

/**
 * La primera vez que corre la versión apuntada, lo cuenta a quien aprueba (`ev: 'updated'`).
 * Una vez: se marca en el propio marcador. Si no se puede contar, se dice y se reintenta en
 * la sesión siguiente.
 */
export async function announceIfNew ({ store, myVersion, vault, log = () => {} }) {
  const cur = await readCurrent(store)
  if (!cur || cur.version !== myVersion || cur.announced !== false) return { did: 'nothing' }
  try { await vault.announceUpdate({ version: myVersion, from: cur.from || null }) } catch (e) {
    log(`[vault-lambda] update: could not tell the approvers that ${myVersion} now runs: ${e?.message || e}`)
    return { did: 'not-told' }
  }
  await writeCurrent(store, { ...cur, announced: true })
  return { did: 'told' }
}

export default { updateCode, announceIfNew, assetName, CHECKED }
