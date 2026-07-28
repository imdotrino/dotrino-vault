/**
 * i18n.js — textos de la TUI en español e inglés (CONVENCIONES §9: bilingüe es/en).
 *
 * Sin dependencias y sin estado global: `dict(lang)` devuelve el diccionario y la
 * TUI guarda el idioma activo en `st.lang`. Las entradas con datos son funciones
 * (`vaultCreated: (n) => …`) para que el orden de las palabras sea el natural de
 * cada idioma en vez de una plantilla con huecos.
 *
 * Idioma inicial: `DOTRINO_LANG` (override por ejecución) → el guardado en
 * `prefs.json` (la última vez que pulsaste `l`) → el locale del sistema
 * (`LC_ALL`/`LC_MESSAGES`/`LANGUAGE`/`LANG`) → español.
 *
 * Español de Ecuador: TUTEO, nunca voseo (CONVENCIONES §9).
 */
import path from 'node:path'
import { dataDir, readJson, writeJson } from '../paths.js'

// --------------------------------- español ---------------------------------

const es = {
  code: 'es',
  langName: 'Español',
  otherLangName: 'English',
  langChanged: 'Idioma: Español',

  // encabezado / estado
  daemonRunning: 'corriendo',
  daemonStopped: 'DETENIDO',
  activeVault: 'Bóveda activa: ',
  noName: '(sin nombre)',
  tooSmall: 'Terminal muy pequeño',
  tooSmallHint: (cols, rows) => `Agranda a ≥ 24×9 (hay ${cols}×${rows}).`,

  // pestañas y títulos
  tabDevices: 'Dispositivos',
  tabSecrets: 'Scopes y variables',
  tabsHint: '   (←→ cambiar)',
  titleProfiles: 'Bóvedas',
  titlePairing: 'Emparejar un dispositivo',
  titlePairMode: 'Emparejar: ¿a qué cuenta entra?',

  // bóvedas (perfiles)
  noPassword: 'sin clave',
  locked: '🔒 bloqueada',
  unlocked: '🔓 abierta',
  passwordOf: (name) => `Contraseña de "${name}"`,
  passwordToEdit: 'necesaria para editar la bóveda',
  unlocking: 'Desbloqueando…',
  loading: 'Cargando…',
  loadingDevices: 'Cargando dispositivos…',
  loadingSecrets: 'Cargando secretos…',
  loadingVaults: 'Cargando bóvedas…',
  switchingVault: 'Cambiando de bóveda…',
  vaultNowActive: (name) => `Bóveda activa: ${name}`,
  newVaultLabel: 'Nombre de la nueva bóveda',
  newVaultHint: 'crea una identidad nueva y vacía',
  nameEmpty: 'El nombre no puede estar vacío',
  creatingVault: 'Creando bóveda…',
  vaultCreated: (name) => `Bóveda creada: ${name}`,
  renameLabel: (name) => `Nuevo nombre para "${name}"`,
  renaming: 'Renombrando…',
  vaultRenamed: 'Bóveda renombrada',
  cantDeleteLast: 'No se puede borrar la única bóveda',
  deleteLabel: (name) => `Escribe "${name}" para BORRARLA (irreversible)`,
  deleteHint: 'se pierde su clave; sus dispositivos dejan de funcionar',
  deleteMismatch: 'Cancelado (el nombre no coincide)',
  deletingVault: 'Borrando bóveda…',
  vaultDeleted: 'Bóveda borrada',
  newPasswordLabel: (name) => `Contraseña nueva para "${name}" (mín. 4)`,
  passwordTooShort: 'La contraseña debe tener al menos 4 caracteres',
  repeatPassword: 'Repite la contraseña',
  passwordMismatch: 'Las contraseñas no coinciden',
  savingPassword: 'Guardando contraseña…',
  passwordSaved: 'Contraseña guardada',
  noPasswordSet: 'Esta bóveda no tiene contraseña',
  removingPassword: 'Quitando contraseña…',
  passwordRemoved: 'Contraseña quitada',
  alreadyUnlocked: 'Ya está desbloqueada',
  vaultUnlocked: 'Bóveda desbloqueada',
  lockingVault: 'Bloqueando…',
  vaultLocked: 'Bóveda bloqueada',

  // dispositivos
  pendingDevice: (id) => ` ⧗ PENDIENTE: ${id}`,
  pendingHint: '  — pulsa A para aprobar, X para rechazar',
  noDevices: '  (sin dispositivos enrolados — pulsa P para emparejar uno)',
  noLabel: '(sin etiqueta)',
  revokedCount: (n) => `  Revocados: ${n}`,
  startingPairing: 'Iniciando emparejamiento…',
  noPending: 'No hay ningún dispositivo pendiente',
  noPendingToReject: 'No hay ningún dispositivo pendiente para rechazar',
  rejecting: 'Rechazando…',
  deviceRejected: 'Dispositivo rechazado',
  revokeConfirm: (id) => `¿Revocar ${id}? Se le ordena autoborrarse al reconectar.`,
  revoking: 'Revocando…',
  deviceRevoked: (id) => `Revocado ${id}`,
  approveLabel: (id) => `Código que MUESTRA el dispositivo ${id}`,
  approveHint: 'el vault no lo conoce: compáralo en la otra pantalla',
  codeMissing: 'Falta el código',
  approving: 'Aprobando…',
  deviceApproved: 'Dispositivo aprobado',
  restartingPairing: 'Reiniciando emparejamiento…',

  // scopes y variables
  noScopes: '  (sin scopes — pulsa N para agregar la primera variable)',
  scopeOf: (ns) => `   (scope vault:secrets:${ns})`,
  removeVarConfirm: (ns, key) => `¿Quitar la variable ${ns}/${key}?`,
  removingVar: 'Quitando variable…',
  varRemoved: 'Variable quitada',
  removeScopeConfirm: (ns, n) => `¿Quitar el scope "${ns}" ENTERO (${n} variable(s))?`,
  removingScope: 'Quitando scope…',
  scopeRemoved: (ns) => `Scope "${ns}" quitado`,
  nsLabel: 'Scope (namespace del servicio)',
  nsHintExisting: (list) => `[a-z0-9-] · existen: ${list}`,
  nsHint: '[a-z0-9-], p. ej. proxy',
  nsInvalid: 'Scope inválido: usa [a-z0-9-]{1,32}',
  keyLabel: (ns) => `Variable en "${ns}" (MAYUSCULAS_CON_GUION_BAJO)`,
  keyHint: '[A-Z0-9_], p. ej. TURN_KEY_ID',
  keyInvalid: 'Clave inválida: usa [A-Z0-9_]{1,64}',
  valueLabel: (ns, key) => `Valor de ${ns}/${key}`,
  valueHint: 'el valor nunca se muestra; se guarda en la bóveda',
  valueEmpty: 'El valor no puede estar vacío',
  savingVar: 'Guardando variable…',
  varSaved: (ns, key) => `Guardado ${ns}/${key}`,

  // emparejamiento — la PREGUNTA es del vault, que es quien lo inicia
  pairModeIntro: 'Un dispositivo puede entrar a una cuenta que ya vive aquí, o estrenar una.',
  pairModeHere: (name) => `Entrar a esta cuenta: ${name}`,
  pairModeHereHint: 'el dispositivo pasa a ver y firmar lo de esta cuenta',
  pairModeNew: 'Estrenar una cuenta nueva en este vault',
  pairModeNewHint: 'se crea aquí, vacía, y el dispositivo entra a ELLA (las otras no se tocan)',
  pairModeAdopt: 'Adoptar la cuenta que trae el dispositivo',
  pairModeAdoptSoon: 'todavía no: el dispositivo aún no sabe entregar la suya',
  newAccountLabel: 'Nombre de la cuenta nueva',
  newAccountHint: 'nace vacía; el dispositivo será su primer invitado',
  accountCreated: (name) => `Cuenta creada: ${name}`,
  pairAccount: (name) => `Cuenta que se comparte: ${name}`,
  pairValid: (min) => `Válido ~${min} min. Escanéalo o abre la URL en el dispositivo.`,
  pairUrl: 'URL: ',
  pairPaste: 'O pega este código en vault.dotrino.com/dispositivos:',
  pairWarning: '⚠ Este código deja LEER tus datos y FIRMAR con tu identidad. No lo compartas.',
  pairConnected: (id) => `⧗ Se conectó: ${id} — pulsa A y escribe el código que muestra.`,
  pairWaiting: 'Esperando a que el dispositivo se conecte…',
  pairQrTooNarrow: (cols, need) => `Agranda el terminal (el QR necesita ${need} cols; hay ${cols}).`,

  // confirmación / entrada
  confirmKeys: '  (s / N)',
  helpInput: 'Enter confirmar · Esc cancelar · Ctrl-U limpiar',
  helpConfirm: 's confirmar · n/Esc cancelar',

  // Barras de ayuda. Las TECLAS son las mismas en los dos idiomas (mnemónico
  // INGLÉS: new/rename/delete/password/unlock/locK/pair/approve/revoke/refresh/
  // language/quit); lo único que se traduce es la palabra que las explica.
  // Segmentos, no una línea: el render recorta del medio si no caben.
  helpProfiles: ['↑↓', 'Enter entrar', 'p emparejar', 'n nueva', 'r renombrar', 'd borrar', 'c clave', 'x quitar-clave', 'u desbloq', 'k bloquear', 'l English', 'q salir'],
  helpDevices: ['←→ pestaña', '↑↓', 'p emparejar', 'a aprobar', 'x rechazar', 'v revocar', 'r refrescar', 'Esc bóvedas', 'l English', 'q salir'],
  helpSecrets: ['←→ pestaña', '↑↓', 'n nueva variable', 'x quitar (variable/scope)', 'r refrescar', 'Esc bóvedas', 'l English', 'q salir'],
  helpPairing: ['a aprobar', 'x rechazar', 'r reiniciar', '↑↓ scroll', 'Esc atrás', 'l English'],
  helpPairMode: ['↑↓', 'Enter elegir', 'Esc atrás', 'l English', 'q salir'],

  // pantalla "daemon caído"
  downTitle: 'El daemon del vault no está corriendo.',
  downBody1: 'La TUI le da órdenes al daemon (custodio de tu clave). Sin él no puede',
  downBody2: 'crear bóvedas, listar dispositivos ni tocar secretos.',
  downStart: '  intentar arrancarlo:  ',
  downRecheck: '  volver a comprobar',
  downLang: '  cambiar a English',
  downQuit: '  salir',
  downDev: 'En desarrollo, arráncalo a mano:  node bin/dotrino-vaultd.js',
  downHeader: 'dotrino-vault   daemon: DETENIDO',
  downHelp: ['S arrancar', 'R comprobar', 'l English', 'Q salir'],
  starting: 'Arrancando el servicio…',
  startingShort: 'Arrancando…',
  stillDown: 'Sigue sin responder',
  startedNotReady: 'Arrancó pero aún no responde; pulsa R',
  startFailed: (err) => `No se pudo arrancar: ${err}`,

  // errores
  errDaemonDown: 'El daemon no está corriendo. Arráncalo: systemctl --user start dotrino-vault (o reinicia la TUI).',
  errNoReply: 'El daemon no respondió.',
  errNotApplied: 'El daemon no aplicó el cambio (revisa los logs del servicio).',
  errNotDeleted: 'El daemon no borró la variable (revisa los logs del servicio).',
  errPairFailed: 'El daemon no inició el emparejamiento.',
  errMasterWithMembers: 'Esta cuenta la manda esta bóveda y tiene otros dispositivos: pásale primero el mando a uno que esté conectado. Si la borras así, se quedan con su llave y sin nadie que pueda volver a firmar el acta.'
}

// ---------------------------------- inglés ----------------------------------

const en = {
  code: 'en',
  langName: 'English',
  otherLangName: 'Español',
  langChanged: 'Language: English',

  daemonRunning: 'running',
  daemonStopped: 'STOPPED',
  activeVault: 'Active vault: ',
  noName: '(unnamed)',
  tooSmall: 'Terminal too small',
  tooSmallHint: (cols, rows) => `Resize to ≥ 24×9 (now ${cols}×${rows}).`,

  tabDevices: 'Devices',
  tabSecrets: 'Scopes & variables',
  tabsHint: '   (←→ switch)',
  titleProfiles: 'Vaults',
  titlePairing: 'Pair a device',
  titlePairMode: 'Pairing: which account does it join?',

  noPassword: 'no password',
  locked: '🔒 locked',
  unlocked: '🔓 unlocked',
  passwordOf: (name) => `Password for "${name}"`,
  passwordToEdit: 'needed to edit this vault',
  unlocking: 'Unlocking…',
  loading: 'Loading…',
  loadingDevices: 'Loading devices…',
  loadingSecrets: 'Loading secrets…',
  loadingVaults: 'Loading vaults…',
  switchingVault: 'Switching vault…',
  vaultNowActive: (name) => `Active vault: ${name}`,
  newVaultLabel: 'Name of the new vault',
  newVaultHint: 'creates a new, empty identity',
  nameEmpty: 'The name cannot be empty',
  creatingVault: 'Creating vault…',
  vaultCreated: (name) => `Vault created: ${name}`,
  renameLabel: (name) => `New name for "${name}"`,
  renaming: 'Renaming…',
  vaultRenamed: 'Vault renamed',
  cantDeleteLast: 'Cannot delete the only vault',
  deleteLabel: (name) => `Type "${name}" to DELETE it (irreversible)`,
  deleteHint: 'its key is lost; its devices stop working',
  deleteMismatch: 'Cancelled (the name does not match)',
  deletingVault: 'Deleting vault…',
  vaultDeleted: 'Vault deleted',
  newPasswordLabel: (name) => `New password for "${name}" (min. 4)`,
  passwordTooShort: 'The password must be at least 4 characters',
  repeatPassword: 'Repeat the password',
  passwordMismatch: 'The passwords do not match',
  savingPassword: 'Saving password…',
  passwordSaved: 'Password saved',
  noPasswordSet: 'This vault has no password',
  removingPassword: 'Removing password…',
  passwordRemoved: 'Password removed',
  alreadyUnlocked: 'Already unlocked',
  vaultUnlocked: 'Vault unlocked',
  lockingVault: 'Locking…',
  vaultLocked: 'Vault locked',

  pendingDevice: (id) => ` ⧗ PENDING: ${id}`,
  pendingHint: '  — press A to approve, X to reject',
  noDevices: '  (no devices enrolled — press P to pair one)',
  noLabel: '(no label)',
  revokedCount: (n) => `  Revoked: ${n}`,
  startingPairing: 'Starting pairing…',
  noPending: 'No device is waiting',
  noPendingToReject: 'No device is waiting to be rejected',
  rejecting: 'Rejecting…',
  deviceRejected: 'Device rejected',
  revokeConfirm: (id) => `Revoke ${id}? It is told to erase itself on reconnect.`,
  revoking: 'Revoking…',
  deviceRevoked: (id) => `Revoked ${id}`,
  approveLabel: (id) => `Code SHOWN by device ${id}`,
  approveHint: 'the vault does not know it: compare it on the other screen',
  codeMissing: 'The code is missing',
  approving: 'Approving…',
  deviceApproved: 'Device approved',
  restartingPairing: 'Restarting pairing…',

  noScopes: '  (no scopes — press N to add the first variable)',
  scopeOf: (ns) => `   (scope vault:secrets:${ns})`,
  removeVarConfirm: (ns, key) => `Remove the variable ${ns}/${key}?`,
  removingVar: 'Removing variable…',
  varRemoved: 'Variable removed',
  removeScopeConfirm: (ns, n) => `Remove the WHOLE scope "${ns}" (${n} variable(s))?`,
  removingScope: 'Removing scope…',
  scopeRemoved: (ns) => `Scope "${ns}" removed`,
  nsLabel: 'Scope (the service namespace)',
  nsHintExisting: (list) => `[a-z0-9-] · existing: ${list}`,
  nsHint: '[a-z0-9-], e.g. proxy',
  nsInvalid: 'Invalid scope: use [a-z0-9-]{1,32}',
  keyLabel: (ns) => `Variable in "${ns}" (UPPERCASE_WITH_UNDERSCORES)`,
  keyHint: '[A-Z0-9_], e.g. TURN_KEY_ID',
  keyInvalid: 'Invalid key: use [A-Z0-9_]{1,64}',
  valueLabel: (ns, key) => `Value of ${ns}/${key}`,
  valueHint: 'the value is never shown; it is kept in the vault',
  valueEmpty: 'The value cannot be empty',
  savingVar: 'Saving variable…',
  varSaved: (ns, key) => `Saved ${ns}/${key}`,

  pairModeIntro: 'A device can join an account that already lives here, or start a new one.',
  pairModeHere: (name) => `Join this account: ${name}`,
  pairModeHereHint: 'the device gets to see and sign for this account',
  pairModeNew: 'Start a new account in this vault',
  pairModeNewHint: 'created here, empty, and the device joins THAT one (the others are untouched)',
  pairModeAdopt: 'Adopt the account the device brings',
  pairModeAdoptSoon: 'not yet: the device cannot hand its own over',
  newAccountLabel: 'Name of the new account',
  newAccountHint: 'born empty; the device will be its first guest',
  accountCreated: (name) => `Account created: ${name}`,
  pairAccount: (name) => `Account being shared: ${name}`,
  pairValid: (min) => `Valid ~${min} min. Scan it or open the URL on the device.`,
  pairUrl: 'URL: ',
  pairPaste: 'Or paste this code into vault.dotrino.com/dispositivos:',
  pairWarning: '⚠ This code lets someone READ your data and SIGN as you. Do not share it.',
  pairConnected: (id) => `⧗ Connected: ${id} — press A and type the code it shows.`,
  pairWaiting: 'Waiting for the device to connect…',
  pairQrTooNarrow: (cols, need) => `Widen the terminal (the QR needs ${need} cols; you have ${cols}).`,

  confirmKeys: '  (y / N)',
  helpInput: 'Enter confirm · Esc cancel · Ctrl-U clear',
  helpConfirm: 'y confirm · n/Esc cancel',

  helpProfiles: ['↑↓', 'Enter open', 'p pair', 'n new', 'r rename', 'd delete', 'c password', 'x drop-password', 'u unlock', 'k lock', 'l Español', 'q quit'],
  helpDevices: ['←→ tab', '↑↓', 'p pair', 'a approve', 'x reject', 'v revoke', 'r refresh', 'Esc vaults', 'l Español', 'q quit'],
  helpSecrets: ['←→ tab', '↑↓', 'n new variable', 'x remove (variable/scope)', 'r refresh', 'Esc vaults', 'l Español', 'q quit'],
  helpPairing: ['a approve', 'x reject', 'r restart', '↑↓ scroll', 'Esc back', 'l Español'],
  helpPairMode: ['↑↓', 'Enter choose', 'Esc back', 'l Español', 'q quit'],

  downTitle: 'The vault daemon is not running.',
  downBody1: 'The TUI gives orders to the daemon (the keeper of your key). Without it',
  downBody2: 'it cannot create vaults, list devices or touch secrets.',
  downStart: '  try to start it:  ',
  downRecheck: '  check again',
  downLang: '  switch to Español',
  downQuit: '  quit',
  downDev: 'In development, start it by hand:  node bin/dotrino-vaultd.js',
  downHeader: 'dotrino-vault   daemon: STOPPED',
  downHelp: ['S start', 'R check', 'l Español', 'Q quit'],
  starting: 'Starting the service…',
  startingShort: 'Starting…',
  stillDown: 'Still not answering',
  startedNotReady: 'It started but does not answer yet; press R',
  startFailed: (err) => `Could not start it: ${err}`,

  errDaemonDown: 'The daemon is not running. Start it: systemctl --user start dotrino-vault (or restart the TUI).',
  errNoReply: 'The daemon did not answer.',
  errNotApplied: 'The daemon did not apply the change (check the service logs).',
  errNotDeleted: 'The daemon did not delete the variable (check the service logs).',
  errPairFailed: 'The daemon did not start the pairing.',
  errMasterWithMembers: 'This vault is in charge of this account and it has other devices: hand the lead over to one that is online first. If you delete it like this, they keep their key with nobody able to sign the record again.'
}

// --------------------------- selección y persistencia -----------------------

export const LANGS = ['es', 'en']

/** Diccionario del idioma pedido (español para cualquier valor desconocido). */
export const dict = (lang) => (lang === 'en' ? en : es)

/** El OTRO idioma (el toggle es binario). */
export const otherLang = (lang) => (lang === 'en' ? 'es' : 'en')

const prefsFile = () => path.join(dataDir(), 'prefs.json')

/** 'es_EC.UTF-8' → 'es'; 'C'/'POSIX'/vacío → null (para caer al siguiente origen). */
const normalize = (v) => {
  const s = String(v || '').toLowerCase()
  if (s.startsWith('en')) return 'en'
  if (s.startsWith('es')) return 'es'
  return null
}

/** Idioma inicial: DOTRINO_LANG → prefs.json → locale del sistema → español. */
export function loadLang () {
  const forced = normalize(process.env.DOTRINO_LANG)
  if (forced) return forced
  const saved = normalize(readJson(prefsFile(), {})?.lang)
  if (saved) return saved
  const locale = process.env.LC_ALL || process.env.LC_MESSAGES || process.env.LANGUAGE || process.env.LANG
  return normalize(locale) || 'es'
}

/** Recuerda el idioma para la próxima vez (junto al resto de preferencias). */
export function saveLang (lang) {
  if (!LANGS.includes(lang)) return false
  try {
    writeJson(prefsFile(), { ...(readJson(prefsFile(), {}) || {}), lang })
    return true
  } catch (_) { return false } // preferencia: nunca romper la TUI por no poder guardarla
}
