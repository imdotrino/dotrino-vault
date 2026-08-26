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
  daemonStale: (running, installed) => `⚠ el servicio corre ${running} y el binario instalado es ${installed}: reinícialo (systemctl --user restart dotrino-vault)`,
  activeVault: 'Bóveda activa: ',
  noName: '(sin nombre)',
  tooSmall: 'Terminal muy pequeño',
  tooSmallHint: (cols, rows) => `Agranda a ≥ 24×9 (hay ${cols}×${rows}).`,

  // pestañas y títulos
  tabDevices: 'Dispositivos',
  tabSecrets: 'Scopes y variables',
  tabMe: 'Perfil',
  // PERMISOS de un dispositivo (§9.1: se dice el beneficio, no el scope del cert).
  titleCaps: 'Permisos del dispositivo',
  capsFor: (id, name) => `Permisos de ${id}${name ? ' · ' + name : ''}`,
  capsNoMember: '  (este dispositivo ya no está en el acta)',
  capsApplyHint: 'Enter marca o desmarca. Cada cambio se aplica y se avisa a tus otros aparatos.',
  capName: {
    sign: 'Firmar como tú',
    store: 'Guardar tus datos',
    read: 'Leer tus datos',
    admin: 'Administrar el perfil'
  },
  capHint: {
    sign: 'usar tu identidad en las apps del ecosistema',
    store: 'escribir en tu bóveda (perfil, contenido, datos sensibles)',
    read: 'ver lo que guardaste',
    admin: 'conectar y quitar dispositivos desde ese aparato, sin venir aquí'
  },
  confirmAdmin: (id) => `¿Dejar que ${id} conecte y quite dispositivos sin venir aquí?`,
  capGiven: (n) => `Concedido: ${n}`,
  capTaken: (n) => `Quitado: ${n}`,
  applyingCaps: 'Aplicando…',
  loadingMembers: 'Cargando el acta…',
  helpCaps: ['↑↓', 'Enter marcar', 'F5 refrescar', 'Esc dispositivos', 'l English', 'q salir'],
  // Perfil del usuario (lo que sincronizan los dispositivos). Solo lectura: se edita en
  // el aparato, no en la máquina donde vive la bóveda.
  loadingProfile: 'Cargando el perfil…',
  noProfile: '  (esta bóveda todavía no tiene perfil)',
  noProfileHint: '  Edita tu nombre o tu foto en un dispositivo emparejado y pulsa F5.',
  profileUpdated: (when) => `  actualizado ${when}`,
  fieldName: 'nombre',
  fieldPhoto: 'foto',
  fieldFirstName: 'nombres',
  fieldLastName: 'apellidos',
  fieldEmail: 'correo',
  fieldPhone: 'teléfono',
  fieldAddress: 'dirección',
  links: 'Enlaces',
  otherData: 'Otros datos',
  hidden: '   (oculto)',
  no: 'no',
  helpMe: ['←→ pestaña', 'F5 refrescar', 'Esc bóvedas', 'l English', 'q salir'],
  tabsHint: '   (←→ cambiar)',
  titleProfiles: 'Bóvedas',
  titlePairing: 'Emparejar un dispositivo',
  titlePairMode: 'Emparejar: ¿a qué cuenta entra?',

  // bóvedas (perfiles)
  noPassword: 'sin clave',
  noPasswordWarn: 'Este perfil no tiene contraseña: una copia de este disco abre las variables privadas.',
  pendingSeal: (owner, kind, who) => kind === 'rotate' ? `${owner}: sin rotar (salió un aparato). Guarda una variable con la contraseña.` : `${owner}: sin llave todavía en ${who}. Se reparte sola con otro aparato del grupo encendido, o al abrir la bóveda.`,
  locked: '🔒 bloqueada',
  unlocked: '🔓 abierta',
  passwordOf: (name) => `Contraseña de "${name}"`,
  passwordToEdit: 'necesaria para abrir la bóveda: sin ella no se ve ni se toca',
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
  passwordTooShort: 'La contraseña debe tener al menos 12 caracteres: usa varias palabras al azar',
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
  // Está en el acta y no puede entrar: o le retiraron el certificado, o se le venció.
  deviceNoAccess: 'SIN ACCESO — está en el acta pero no puede entrar',
  deviceDebt: (n) => `no abre ${n}`,
  thisVault: 'esta bóveda (manda ella)',
  cantRemoveMaster: 'Esta bóveda es la que manda: no se quita a sí misma.',
  revokedCount: (n) => `  Revocados: ${n}`,
  startingPairing: 'Iniciando emparejamiento…',
  noPending: 'No hay ningún dispositivo pendiente',
  noPendingToReject: 'No hay ningún dispositivo pendiente para rechazar',
  rejecting: 'Rechazando…',
  deviceRejected: 'Dispositivo rechazado',
  revokeConfirm: (id) => `¿Quitar ${id} del perfil? Sale del acta y se le retiran los certificados ya. Lo que tenga guardado se le borra cuando se conecte: si está apagado, sigue ahí hasta entonces.`,
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

  // CARGAR VARIAS DE UNA VEZ (tecla c). Una a una, cada variable es un cambio de
  // configuración y el servicio se reinicia a media carga; juntas, se reinicia una vez.
  loadLabel: (ns) => `Cargar varias en "${ns}"`,
  loadHint: 'CLAVE=valor CLAVE2=valor2 · o la ruta de un archivo .env',
  loadNoFile: (f) => `No se pudo leer ${f}`,
  loadingVars: 'Cargando variables…',
  loadedVars: (n, ns) => `${n} variables cargadas en ${ns} · un solo aviso de cambio`,
  envErr: {
    shape: (e) => `línea ${e.line}: no tiene la forma CLAVE=valor`,
    key: (e) => `línea ${e.line}: «${e.key}» va en MAYUSCULAS_CON_GUION_BAJO`,
    novalue: (e) => `línea ${e.line}: ${e.key} no tiene valor`,
    dup: (e) => `línea ${e.line}: ${e.key} ya venía en la línea ${e.first}`,
    empty: () => 'No hay ninguna variable que cargar'
  },
  loadNothing: 'No se cargó nada:',
  varPublic: 'pública',
  newVarPublicAsk: '¿Que su valor se pueda VER desde la consola remota? (las demás no salen de esta máquina)',
  makePublicConfirm: '¿Dejar que su valor se vea desde la consola remota?',
  changingVisibility: 'Cambiando visibilidad…',
  nowPublic: 'Ahora su valor se puede ver desde la consola remota',
  nowPrivate: 'Ahora su valor no sale de esta máquina',

  // variables de UN aparato (Dispositivos → tecla e). Las del scope las comparten todos
  // los aparatos que sirven ese namespace; estas las lee solo él, y le ganan.
  titleDevVars: 'Variables del dispositivo',
  devVarsFor: (id, name) => `Variables de ${id}${name ? ' · ' + name : ''}`,
  devVarsService: (cn) => `servicio «${cn}» — solo las lee este aparato, y pisan a las del scope`,
  noDevVars: '(sin variables propias — pulsa N para agregar la primera)',
  devVarsOnlyServices: 'Solo un servicio lee variables, y este aparato no lo es',
  devVarsElsewhere: 'Las variables de UN aparato se ponen en Dispositivos (tecla e).',
  removeDevVarConfirm: (id, key) => `¿Quitar la variable ${key} de ${id}?`,

  // emparejamiento — la PREGUNTA es del vault, que es quien lo inicia
  pairModeIntro: 'Un dispositivo puede entrar a una cuenta que ya vive aquí, o estrenar una.',
  pairModeHere: (name) => `Entrar a esta cuenta: ${name}`,
  pairModeHereHint: 'el dispositivo pasa a ver y firmar lo de esta cuenta',
  pairModeNew: 'Estrenar una cuenta nueva en este vault',
  pairModeNewHint: 'se crea aquí, vacía, y el dispositivo entra a ELLA (las otras no se tocan)',
  pairModeService: 'Conectar un servicio (proxy, geo…)',
  pairModeServiceHint: 'entra a esta cuenta pero solo lee SUS variables: no firma ni ve tu contenido',
  pairModeAdopt: 'Adoptar la cuenta que trae el dispositivo',
  pairModeAdoptSoon: 'todavía no: el dispositivo aún no sabe entregar la suya',
  serviceNsLabel: '¿Qué servicio es? (proxy, geo, results…)',
  serviceNsHint: 'minúsculas, sin espacios; es el nombre con el que ese programa pide su configuración',
  serviceNsBad: 'Nombre no válido: minúsculas, números y guiones (hasta 32)',
  pairService: (ns) => `Este QR entrega un SERVICIO «${ns}»: solo podrá leer las variables de ${ns}.`,
  newAccountLabel: 'Nombre de la cuenta nueva',
  newAccountHint: 'nace vacía; el dispositivo será su primer invitado',
  accountCreated: (name) => `Cuenta creada: ${name}`,
  discardingAccount: 'Descartando la cuenta…',
  accountDiscarded: 'Cuenta descartada: nadie llegó a entrar en ella',
  confirmDiscardAccount: 'La cuenta se creó para este emparejamiento y quedó vacía. ¿La descarto?',
  // Cuenta + vigencia en UNA línea: cada línea de cabecera es una fila menos de QR
  // visible antes de tener que hacer scroll.
  pairAccount: (name, min) => `Cuenta que se comparte: ${name}  ·  válido ~${min} min`,
  pairScan: 'Escanéalo, o abre esta dirección en el dispositivo:',
  pairUrl: 'URL: ',
  pairPaste: 'O pega este código en vault.dotrino.com/vault:',
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
  // La barra dice lo que se PUEDE hacer AHORA, no todo lo que existe: aprobar/rechazar solo
  // valen si hay alguien esperando, y renombrar/revocar solo si hay un aparato seleccionado.
  // Anunciar teclas muertas confunde y además las quema para otros usos.
  // `e variables` solo en un SERVICIO: es el único que las lee, así que en un teléfono
  // era una tecla que solo sabía decir que no.
  helpDevices: ({ pending, hasDevices, isService } = {}) => [
    '←→ pestaña', '↑↓', 'p emparejar',
    ...(pending ? ['a aprobar', 'x rechazar'] : []),
    ...(hasDevices ? ['r renombrar', 'c permisos'] : []),
    ...(isService ? ['e variables'] : []),
    ...(hasDevices ? ['v revocar'] : []),
    'F5 refrescar', 'Esc bóvedas', 'l English', 'q salir'
  ],
  renameDeviceLabel: (id) => `¿Cómo quieres llamar a ${id}?`,
  renameDeviceHint: 'el nombre con el que lo reconoces (Esc cancela)',
  deviceRenamed: (n) => `Ahora se llama «${n}»`,
  helpSecrets: ({ hasSecrets } = {}) => [
    '←→ pestaña', '↑↓', 'n nueva variable', 'i cargar varias',
    ...(hasSecrets ? ['v ver valor', 't pública/privada', 'x quitar (variable/scope)'] : []),
    'F5 refrescar', 'Esc bóvedas', 'l English', 'q salir'
  ],
  helpDevVars: ({ hasVars } = {}) => [
    '↑↓', 'n nueva variable', 'i cargar varias',
    ...(hasVars ? ['v ver valor', 't pública/privada', 'x quitar'] : []),
    'F5 refrescar', 'Esc dispositivos', 'l English', 'q salir'
  ],
  // Ver el valor de una privada: lo único que la contraseña guarda en esta máquina.
  revealTitle: 'Ver el valor',
  revealAsk: 'Contraseña del perfil (para ver el valor)',
  revealHint: 'sin ella no se puede abrir: es lo único que la guarda (Esc cancela)',
  revealing: 'abriendo…',
  revealed: (k, v) => `${k} = ${v}`,
  revealNoPwd: 'Este perfil no tiene contraseña: se abre con la llave de esta máquina.',
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
  // El código NO es la contraseña de la bóveda: son los seis dígitos que el aparato
  // enseña en su pantalla. Si no coincide, la bóveda no firma nada y el aparato sigue
  // esperando ahí, así que se puede volver a intentar con A.
  errWrongCode: 'El código no coincide con el que muestra el dispositivo: no se emitió ningún certificado. Míralo otra vez y pulsa A.',
  errProfileLocked: 'Bóveda bloqueada: ábrela con su contraseña',
  errWrongPassword: (n) => `Contraseña incorrecta${n ? ` — van ${n} intentos fallidos` : ''}`,
  errTooManyTries: (s) => `Demasiados intentos: espera ${s || '?'} s antes de volver a probar`,
  errMasterWithMembers: 'Esta bóveda es el Master de esta cuenta y hay otros dispositivos: pásale primero el Master a uno que esté conectado. Si la borras así, se quedan con su llave y sin nadie que pueda volver a firmar el acta.'
}

// ---------------------------------- inglés ----------------------------------

const en = {
  code: 'en',
  langName: 'English',
  otherLangName: 'Español',
  langChanged: 'Language: English',

  daemonRunning: 'running',
  daemonStopped: 'STOPPED',
  daemonStale: (running, installed) => `⚠ the service runs ${running} but the installed binary is ${installed}: restart it (systemctl --user restart dotrino-vault)`,
  activeVault: 'Active vault: ',
  tooSmall: 'Terminal too small',
  tooSmallHint: (cols, rows) => `Resize to ≥ 24×9 (now ${cols}×${rows}).`,

  tabDevices: 'Devices',
  tabSecrets: 'Scopes & variables',
  tabMe: 'Profile',
  titleCaps: 'Device permissions',
  capsFor: (id, name) => `Permissions for ${id}${name ? ' · ' + name : ''}`,
  capsNoMember: '  (this device is no longer in the record)',
  capsApplyHint: 'Enter ticks or unticks. Each change applies and your other devices are told.',
  capName: {
    sign: 'Sign as you',
    store: 'Save your data',
    read: 'Read your data',
    admin: 'Manage the profile'
  },
  capHint: {
    sign: 'use your identity across the ecosystem apps',
    store: 'write to your vault (profile, content, sensitive data)',
    read: 'see what you saved',
    admin: 'connect and remove devices from that device, without coming here'
  },
  confirmAdmin: (id) => `Let ${id} connect and remove devices without coming here?`,
  capGiven: (n) => `Granted: ${n}`,
  capTaken: (n) => `Removed: ${n}`,
  applyingCaps: 'Applying…',
  loadingMembers: 'Loading the record…',
  helpCaps: ['↑↓', 'Enter tick', 'F5 refresh', 'Esc devices', 'l Español', 'q quit'],
  loadingProfile: 'Loading profile…',
  noProfile: '  (this vault has no profile yet)',
  noProfileHint: '  Edit your name or photo on a paired device and press F5.',
  profileUpdated: (when) => `  updated ${when}`,
  fieldName: 'name',
  fieldPhoto: 'photo',
  fieldFirstName: 'first name',
  fieldLastName: 'last name',
  fieldEmail: 'email',
  fieldPhone: 'phone',
  fieldAddress: 'address',
  links: 'Links',
  otherData: 'Other data',
  hidden: '   (hidden)',
  noName: '(no name)',
  no: 'no',
  helpMe: ['←→ tab', 'F5 refresh', 'Esc vaults', 'l Español', 'q quit'],
  tabsHint: '   (←→ switch)',
  titleProfiles: 'Vaults',
  titlePairing: 'Pair a device',
  titlePairMode: 'Pairing: which account does it join?',

  noPassword: 'no password',
  noPasswordWarn: 'This profile has no password: a copy of this disk opens the private variables.',
  pendingSeal: (owner, kind, who) => kind === 'rotate' ? `${owner}: not rotated (a device left). Save a variable with the password.` : `${owner}: no key yet on ${who}. It is handed out by another device of the group that is on, or when the vault is opened.`,
  locked: '🔒 locked',
  unlocked: '🔓 unlocked',
  passwordOf: (name) => `Password for "${name}"`,
  passwordToEdit: 'needed to open this vault: without it, nothing is shown or touched',
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
  passwordTooShort: 'The password must be at least 12 characters: use several random words',
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
  deviceNoAccess: 'NO ACCESS — it is on the record but cannot get in',
  deviceDebt: (n) => `cannot open ${n}`,
  thisVault: 'this vault (it is the Master)',
  cantRemoveMaster: 'This vault is the Master: it does not remove itself.',
  revokedCount: (n) => `  Revoked: ${n}`,
  startingPairing: 'Starting pairing…',
  noPending: 'No device is waiting',
  noPendingToReject: 'No device is waiting to be rejected',
  rejecting: 'Rejecting…',
  deviceRejected: 'Device rejected',
  revokeConfirm: (id) => `Remove ${id} from the profile? It leaves the record and its certificates are withdrawn right away. What it has stored is erased when it connects: if it is switched off, it stays there until then.`,
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

  loadLabel: (ns) => `Load several into "${ns}"`,
  loadHint: 'KEY=value KEY2=value2 · or the path to a .env file',
  loadNoFile: (f) => `Could not read ${f}`,
  loadingVars: 'Loading variables…',
  loadedVars: (n, ns) => `${n} variables loaded into ${ns} · a single change notice`,
  envErr: {
    shape: (e) => `line ${e.line}: not in the form KEY=value`,
    key: (e) => `line ${e.line}: "${e.key}" must be UPPERCASE_WITH_UNDERSCORES`,
    novalue: (e) => `line ${e.line}: ${e.key} has no value`,
    dup: (e) => `line ${e.line}: ${e.key} already came on line ${e.first}`,
    empty: () => 'There is no variable to load'
  },
  loadNothing: 'Nothing was loaded:',
  varPublic: 'public',
  newVarPublicAsk: 'Let its value be SEEN from the remote console? (the rest never leave this machine)',
  makePublicConfirm: 'Let its value be seen from the remote console?',
  changingVisibility: 'Changing visibility…',
  nowPublic: 'Its value can now be seen from the remote console',
  nowPrivate: 'Its value no longer leaves this machine',

  // variables de UN aparato (Dispositivos → tecla e)
  titleDevVars: 'Device variables',
  devVarsFor: (id, name) => `Variables of ${id}${name ? ' · ' + name : ''}`,
  devVarsService: (cn) => `“${cn}” service — only this device reads them, and they override the scope ones`,
  noDevVars: '(no variables of its own — press N to add the first one)',
  devVarsOnlyServices: 'Only a service reads variables, and this device is not one',
  devVarsElsewhere: 'Variables for ONE device are set in Devices (key e).',
  removeDevVarConfirm: (id, key) => `Remove variable ${key} from ${id}?`,

  pairModeIntro: 'A device can join an account that already lives here, or start a new one.',
  pairModeHere: (name) => `Join this account: ${name}`,
  pairModeHereHint: 'the device gets to see and sign for this account',
  pairModeNew: 'Start a new account in this vault',
  pairModeNewHint: 'created here, empty, and the device joins THAT one (the others are untouched)',
  pairModeService: 'Connect a service (proxy, geo…)',
  pairModeServiceHint: 'joins this account but only reads ITS variables: it neither signs nor sees your content',
  pairModeAdopt: 'Adopt the account the device brings',
  pairModeAdoptSoon: 'not yet: the device cannot hand its own over',
  serviceNsLabel: 'Which service is it? (proxy, geo, results…)',
  serviceNsHint: 'lowercase, no spaces; it is the name that program uses to ask for its settings',
  serviceNsBad: 'Invalid name: lowercase letters, digits and dashes (up to 32)',
  pairService: (ns) => `This QR hands out a SERVICE “${ns}”: it will only read ${ns}’s variables.`,
  newAccountLabel: 'Name of the new account',
  newAccountHint: 'born empty; the device will be its first guest',
  accountCreated: (name) => `Account created: ${name}`,
  discardingAccount: 'Discarding the account…',
  accountDiscarded: 'Account discarded: nobody got to join it',
  confirmDiscardAccount: 'The account was created for this pairing and is empty. Discard it?',
  pairAccount: (name, min) => `Account being shared: ${name}  ·  valid ~${min} min`,
  pairScan: 'Scan it, or open this address on the device:',
  pairUrl: 'URL: ',
  pairPaste: 'Or paste this code into vault.dotrino.com/vault:',
  pairWarning: '⚠ This code lets someone READ your data and SIGN as you. Do not share it.',
  pairConnected: (id) => `⧗ Connected: ${id} — press A and type the code it shows.`,
  pairWaiting: 'Waiting for the device to connect…',
  pairQrTooNarrow: (cols, need) => `Widen the terminal (the QR needs ${need} cols; you have ${cols}).`,

  confirmKeys: '  (y / N)',
  helpInput: 'Enter confirm · Esc cancel · Ctrl-U clear',
  helpConfirm: 'y confirm · n/Esc cancel',

  helpProfiles: ['↑↓', 'Enter open', 'p pair', 'n new', 'r rename', 'd delete', 'c password', 'x drop-password', 'u unlock', 'k lock', 'l Español', 'q quit'],
  helpDevices: ({ pending, hasDevices, isService } = {}) => [
    '←→ tab', '↑↓', 'p pair',
    ...(pending ? ['a approve', 'x reject'] : []),
    ...(hasDevices ? ['r rename', 'c permissions'] : []),
    ...(isService ? ['e variables'] : []),
    ...(hasDevices ? ['v revoke'] : []),
    'F5 refresh', 'Esc vaults', 'l Español', 'q quit'
  ],
  renameDeviceLabel: (id) => `What do you want to call ${id}?`,
  renameDeviceHint: 'the name you recognise it by (Esc cancels)',
  deviceRenamed: (n) => `Now called "${n}"`,
  helpSecrets: ({ hasSecrets } = {}) => [
    '←→ tab', '↑↓', 'n new variable', 'i load several',
    ...(hasSecrets ? ['v show value', 't public/private', 'x remove (variable/scope)'] : []),
    'F5 refresh', 'Esc vaults', 'l Español', 'q quit'
  ],
  helpDevVars: ({ hasVars } = {}) => [
    '↑↓', 'n new variable', 'i load several',
    ...(hasVars ? ['v show value', 't public/private', 'x remove'] : []),
    'F5 refresh', 'Esc devices', 'l Español', 'q quit'
  ],
  revealTitle: 'Show the value',
  revealAsk: 'Profile password (to show the value)',
  revealHint: 'without it there is no way to open it: it is the only thing guarding it (Esc cancels)',
  revealing: 'opening…',
  revealed: (k, v) => `${k} = ${v}`,
  revealNoPwd: 'This profile has no password: it opens with this machine key.',
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
  errWrongCode: 'The code does not match the one shown by the device: no certificate was issued. Check it and press A again.',
  errProfileLocked: 'Vault locked: open it with its password',
  errWrongPassword: (n) => `Wrong password${n ? ` — ${n} failed attempts so far` : ''}`,
  errTooManyTries: (s) => `Too many attempts: wait ${s || '?'} s before trying again`,
  errMasterWithMembers: 'This vault is the Master of this account and it has other devices: hand the Master over to one that is online first. If you delete it like this, they keep their key with nobody able to sign the record again.'
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
