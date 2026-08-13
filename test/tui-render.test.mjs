/**
 * Render headless de la TUI: dibuja cada pantalla en muchos estados (incluidos
 * vacíos/nulos, modo entrada, confirmación y emparejamiento) con un `term` falso.
 * No prueba la interacción; prueba que el dibujo NUNCA lanza y respeta el alto y
 * el ancho del terminal (que es donde se rompen las TUIs).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { makeTheme, widthOf, trunc } from '../src/tui/term.js'
import { __test as V } from '../src/tui/app.js'

function fakeTerm (cols = 80, rows = 24) {
  let last = []
  return {
    t: makeTheme(), // sin TTY => sin color (texto plano)
    size: () => ({ cols, rows }),
    // Reproduce el recorte del term real (única fuente de recorte, term.js).
    render: (lines) => { last = lines.map((l) => trunc(l ?? '', cols)) },
    get last () { return last }
  }
}

function baseState (over = {}) {
  return {
    screen: 'profiles',
    sel: { profiles: 0, devices: 0, secrets: 0, caps: 0, devvars: 0 },
    me: null,
    scroll: {},
    profiles: { current: 'p1', profiles: [{ id: 'p1', name: 'Perfil 1', protected: false, locked: false, current: true, fingerprint: 'fp1' }] },
    devices: { issued: [], revoked: [] },
    secrets: { ns: {}, dev: [] },
    pending: null,
    pairing: null,
    state: { version: 'test' },
    daemonUp: true,
    busy: null,
    flash: null,
    input: null,
    confirm: null,
    ...over
  }
}

function assertClean (term, cols, rows) {
  const lines = term.last
  assert.equal(lines.length, rows, 'devuelve exactamente `rows` líneas')
  for (const l of lines) assert.ok(widthOf(l) <= cols, `línea no excede ${cols}: ${JSON.stringify(l)}`)
  // Las barras (header/ayuda) ocupan TODO el ancho.
  assert.equal(widthOf(lines[0]), cols, 'header bar llena el ancho')
  assert.equal(widthOf(lines[rows - 1]), cols, 'help bar llena el ancho')
}

test('render de todas las pantallas no lanza y respeta el tamaño', () => {
  for (const [cols, rows] of [[80, 24], [40, 12], [120, 40], [30, 10]]) {
    for (const screen of ['profiles', 'devices', 'secrets', 'pairing']) {
      const term = fakeTerm(cols, rows)
      const st = baseState({ screen })
      if (screen === 'pairing') st.pairing = { url: 'https://vault.dotrino.com/dispositivos#vault=AAAA', payload: '{"v":2,"token":"tok"}', b64: 'AAAA', expiresAt: Date.now() + 200000 }
      V.render(term, st)
      assertClean(term, cols, rows)
    }
  }
})

test('render con datos ricos + modos (input/confirm/flash/busy)', () => {
  const rich = {
    profiles: {
      current: 'p2',
      profiles: [
        { id: 'p1', name: 'Personal', protected: true, locked: true, current: false, fingerprint: 'aaaa1111' },
        { id: 'p2', name: 'Trabajo', protected: true, locked: false, current: true, fingerprint: 'bbbb2222' },
        { id: 'p3', name: '', protected: false, locked: false, current: false, fingerprint: 'cccc3333' }
      ]
    },
    devices: {
      issued: [
        { deviceId: 'AB12-CD34', label: 'móvil 🔒', scope: ['vault:sign', 'vault:read', 'vault:store'], exp: Date.now() + 8.64e7, nonce: 'n1' },
        { deviceId: 'EF56-7890', label: '', scope: ['vault:secrets:proxy'], exp: null, nonce: 'n2' }
      ],
      revoked: [{ nonce: 'n0' }]
    },
    secrets: {
      ns: {
        proxy: [{ key: 'TURN_KEY_ID', public: false }, { key: 'TURN_SECRET', public: false }],
        geo: [{ key: 'API_TOKEN', public: true }]
      },
      dev: [{ pub: 'PUB2', id: 'EF56-7890', label: '', cn: 'proxy', orphan: false, keys: [{ key: 'PORT', public: true }, { key: 'PUBLIC_URL', public: false }] }]
    }
  }
  const modes = [
    { screen: 'profiles', ...rich },
    { screen: 'devices', ...rich, pending: { deviceId: 'ZZ99-YY88' } },
    { screen: 'secrets', ...rich },
    { screen: 'me', ...rich },
    { screen: 'caps', ...rich },
    { screen: 'caps', ...rich, capsFor: { pub: 'PUB1', deviceId: 'AB12-CD34' }, members: [{ pub: 'PUB1', id: 'AB12-CD34', label: 'móvil', caps: ['sign', 'read'] }] },
    // Variables de UN aparato: con ellas, sin ellas, y sin aparato elegido.
    { screen: 'devvars', ...rich, varsFor: { pub: 'PUB2', deviceId: 'EF56-7890', label: 'proxy de casa', cn: 'proxy' } },
    { screen: 'devvars', ...rich, varsFor: { pub: 'PUB-SIN-VARS', deviceId: 'AB12-CD34', label: '', cn: 'geo' } },
    { screen: 'devvars', ...rich },
    { screen: 'me', ...rich, me: null },
    { screen: 'me', ...rich, me: undefined },
    { screen: 'secrets', ...rich, input: { label: 'Valor', value: 'topsecret', mask: true, hint: 'no se muestra' } },
    { screen: 'devices', ...rich, confirm: { text: '¿Revocar AB12-CD34?' } },
    { screen: 'profiles', ...rich, flash: { text: 'Guardado', kind: 'ok', at: Date.now() } },
    { screen: 'secrets', ...rich, flash: { text: 'Error grave', kind: 'danger', at: Date.now() } },
    { screen: 'profiles', ...rich, busy: 'Cargando…' }
  ]
  for (const over of modes) {
    const term = fakeTerm(80, 24)
    V.render(term, baseState(over))
    assertClean(term, 80, 24)
  }
})

test('terminal muy pequeño: no lanza y no desborda', () => {
  for (const [cols, rows] of [[20, 6], [10, 4], [80, 8]]) {
    const term = fakeTerm(cols, rows)
    V.render(term, baseState({ screen: 'profiles' }))
    assert.ok(term.last.length <= Math.max(rows, 2))
    for (const l of term.last) assert.ok(widthOf(l) <= cols)
  }
})

test('render sin datos cargados todavía (todo null)', () => {
  const term = fakeTerm(80, 24)
  const st = baseState({ profiles: null, devices: null, secrets: null })
  for (const screen of ['profiles', 'devices', 'secrets']) {
    st.screen = screen
    V.render(term, st)
    assertClean(term, 80, 24)
  }
})

test('en inglés: todas las pantallas dibujan igual de bien', () => {
  for (const [cols, rows] of [[80, 24], [40, 12], [120, 40]]) {
    for (const screen of ['profiles', 'devices', 'secrets', 'pairing']) {
      const term = fakeTerm(cols, rows)
      const st = baseState({ screen, lang: 'en' })
      if (screen === 'pairing') st.pairing = { url: 'https://vault.dotrino.com/dispositivos#vault=AAAA', payload: '{"v":2,"token":"tok"}', b64: 'AAAA', expiresAt: Date.now() + 200000, profileName: 'Work' }
      V.render(term, st)
      assertClean(term, cols, rows)
    }
  }
})

test('el idioma cambia el texto (pestañas, título y ayuda), no el tamaño', () => {
  const term = fakeTerm(100, 24)
  V.render(term, baseState({ screen: 'devices', lang: 'en' }))
  assert.match(term.last[3], /Devices/)
  assert.match(term.last[3], /Scopes & variables/)
  assert.match(term.last[23], /q quit/)

  V.render(term, baseState({ screen: 'profiles', lang: 'en' }))
  assert.match(term.last[3], /Vaults/)
  assert.match(term.last[1], /Active vault/)

  V.render(term, baseState({ screen: 'profiles', lang: 'es' }))
  assert.match(term.last[3], /Bóvedas/)
  assert.match(term.last[23], /q salir/)
})

test('la barra de ayuda siempre deja ver el idioma y la salida', () => {
  // En 80 columnas la ayuda de Bóvedas no cabe entera: se recorta del MEDIO.
  for (const lang of ['es', 'en']) {
    for (const cols of [120, 80, 60, 40]) {
      const term = fakeTerm(cols, 24)
      V.render(term, baseState({ screen: 'profiles', lang }))
      const help = term.last[23]
      assert.ok(/ l /.test(help) || /·\s*l /.test(help), `falta la tecla de idioma en ${cols} cols (${lang}): ${help}`)
      assert.match(help, /q (salir|quit)/, `falta la salida en ${cols} cols (${lang})`)
      assert.equal(widthOf(help), cols)
    }
  }
})

test('fitHelp respeta el ancho y conserva la cola', () => {
  const segs = ['↑↓', 'aaaa uno', 'bbbb dos', 'cccc tres', 'dddd cuatro', 'l English', 'q salir']
  assert.equal(V.fitHelp(segs, 200), segs.join(' · '))
  for (const cols of [80, 40, 30, 20]) {
    const out = V.fitHelp(segs, cols)
    assert.ok(out.includes('l English') && out.includes('q salir'), `cola perdida en ${cols}: ${out}`)
    if (cols >= 30) assert.ok(widthOf(out) + 1 <= cols, `no cabe en ${cols}: ${out}`)
  }
})

test('antes del QR, el vault PREGUNTA a qué cuenta entra el dispositivo', () => {
  const t = makeTheme()
  for (const [lang, aqui, nueva] of [['es', /Entrar a esta cuenta: Perfil 1/, /Estrenar una cuenta nueva/], ['en', /Join this account: Perfil 1/, /Start a new account/]]) {
    const rows = V.pairModeRows(baseState({ screen: 'pairmode', lang }), t)
    const opciones = rows.filter((r) => r.sel)
    assert.equal(opciones.length, 2, 'hoy se puede responder de dos formas')
    assert.deepEqual(opciones.map((r) => r.meta.mode), ['here', 'new'])
    assert.match(rows.map((r) => r.text).join('\n'), aqui)
    assert.match(rows.map((r) => r.text).join('\n'), nueva)
    // La tercera (adoptar la cuenta del dispositivo) se nombra pero NO se puede elegir.
    assert.match(rows.map((r) => r.text).join('\n'), lang === 'es' ? /Adoptar la cuenta que trae/ : /Adopt the account the device brings/)
    assert.ok(!opciones.some((r) => r.meta.mode === 'adopt'))
  }

  // Y se dibuja entera, en los dos idiomas y en terminales chicos.
  for (const lang of ['es', 'en']) {
    for (const [cols, rows] of [[80, 24], [40, 12]]) {
      const term = fakeTerm(cols, rows)
      V.render(term, baseState({ screen: 'pairmode', lang }))
      assertClean(term, cols, rows)
    }
  }
})

test('la pantalla de emparejar dice DE QUÉ CUENTA sale el QR', () => {
  const t = makeTheme()
  const st = baseState({ screen: 'pairing' })
  st.pairing = { url: 'https://vault.dotrino.com/dispositivos#vault=AAAA', payload: '{"v":2}', b64: 'AAAA', expiresAt: Date.now() + 200000, profile: 'p9', profileName: 'Trabajo' }
  assert.match(V.pairingBody(st, t, 80, 20)[0], /Cuenta que se comparte: Trabajo/)

  // Sin nombre en el pair.json, cae al de la bóveda activa (nunca queda vacío).
  st.pairing.profileName = ''
  assert.match(V.pairingBody(st, t, 80, 20)[0], /Cuenta que se comparte: Perfil 1/)

  st.lang = 'en'
  assert.match(V.pairingBody(st, t, 80, 20)[0], /Account being shared/)
})

test('el QR se dibuja cuando cabe de ancho, y el código pegable es base64', () => {
  const t = makeTheme()
  const st = baseState({ screen: 'pairing' })
  st.pairing = { url: 'https://vault.dotrino.com/d#v=AAAA', payload: '{"v":2}', b64: 'eyJ2IjoyfQ', expiresAt: Date.now() + 200000 }
  const body = V.pairingBody(st, t, 80, 20)
  const text = body.join('\n')
  // El QR debe aparecer (líneas con escapes ANSI de bloques Unicode).
  assert.match(text, /\x1b\[[0-9;]*m▀/)
  // El código pegable es el base64, no el JSON crudo.
  assert.match(text, /eyJ2IjoyfQ/)
  assert.doesNotMatch(text, /"v":2/)
})

/**
 * El QR de un emparejamiento REAL tiene que caber en una terminal normal. Es la
 * razón de ser del formato compacto: con el JSON de antes salía de 69 módulos
 * (77×39 con la zona de silencio) y no había ventana que lo mostrara entero.
 */
test('el QR de una invitación real cabe en una terminal normal', async () => {
  const { inviteUrl } = await import('../lib/src/invite.js')
  const { qrToString } = await import('../src/qr.js')
  const par = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, true, ['sign', 'verify'])
  const hex = (n) => [...crypto.getRandomValues(new Uint8Array(n))].map((b) => b.toString(16).padStart(2, '0')).join('')
  const qr = {
    v: 2,
    iss: JSON.stringify(await crypto.subtle.exportKey('jwk', par.publicKey)),
    proxy: 'wss://proxy.dotrino.com',
    token: hex(12),
    sn: hex(12),
    m: 'join',
    acct: 'Perfil 1'
  }
  const lineas = qrToString(inviteUrl(qr)).replace(/\n$/, '').split('\n')
  const ancho = Math.max(...lineas.map((l) => l.replace(/\x1b\[[0-9;]*m/g, '').length))
  assert.ok(ancho <= 53, `el QR mide ${ancho} columnas`)
  assert.ok(lineas.length <= 27, `el QR mide ${lineas.length} filas`)

  // Y se dibuja de verdad en la pantalla de emparejar de una terminal de 80 columnas.
  const st = baseState({ screen: 'pairing' })
  st.pairing = { url: inviteUrl(qr), b64: 'x', payload: '{}', expiresAt: Date.now() + 200000 }
  const text = V.pairingBody(st, makeTheme(), 80, 40).join('\n')
  assert.match(text, /\x1b\[[0-9;]*m▀/)
})

test('scrollBody desplaza líneas planas sin perder el ancho', () => {
  const lines = ['a', 'b', 'c', 'd', 'e']
  const ref = { value: 0 }
  assert.deepEqual(V.scrollBody(lines, 3, ref), ['a', 'b', 'c'])
  ref.value = 2
  assert.deepEqual(V.scrollBody(lines, 3, ref), ['c', 'd', 'e'])
  ref.value = 10
  assert.deepEqual(V.scrollBody(lines, 3, ref), ['c', 'd', 'e'])
  assert.equal(ref.value, 2)
})

test('Dispositivos y Scopes muestran la barra de pestañas; Bóvedas no', () => {
  const term = fakeTerm(80, 24)
  V.render(term, baseState({ screen: 'devices' }))
  const devicesLine3 = term.last[3]
  assert.match(devicesLine3, /Dispositivos/)
  assert.match(devicesLine3, /Scopes y variables/)
  assert.match(devicesLine3, /cambiar/)

  V.render(term, baseState({ screen: 'secrets' }))
  assert.match(term.last[3], /Dispositivos/)
  assert.match(term.last[3], /Scopes y variables/)

  V.render(term, baseState({ screen: 'profiles' }))
  assert.match(term.last[3], /Bóvedas/)
  assert.doesNotMatch(term.last[3], /cambiar/)
})


test('DOS SITIOS: el scope en su pestaña, el aparato en la suya (y una apunta a la otra)', () => {
  const term = fakeTerm(100, 24)
  const secrets = {
    ns: { proxy: [{ key: 'TURN_KEY_ID', public: false }] },
    dev: [{ pub: 'PUB2', id: 'EF56-7890', label: '', cn: 'proxy', orphan: false, keys: [{ key: 'PORT', public: true }] }]
  }

  // La pestaña de scopes lista lo COMPARTIDO y no repite lo del aparato: dice dónde está.
  V.render(term, baseState({ screen: 'secrets', secrets }))
  const scopes = term.last.join('\n')
  assert.match(scopes, /TURN_KEY_ID/)
  assert.doesNotMatch(scopes, /PORT/, 'lo del aparato no se duplica aquí')
  assert.match(scopes, /Dispositivos \(tecla e\)/, 'y se dice dónde se pone')

  // La del aparato lista lo suyo, con el servicio que es (dato, no explicación).
  V.render(term, baseState({
    screen: 'devvars',
    secrets,
    varsFor: { pub: 'PUB2', deviceId: 'EF56-7890', label: 'proxy de casa', cn: 'proxy' }
  }))
  const vars = term.last.join('\n')
  assert.match(vars, /EF56-7890/)
  assert.match(vars, /PORT/)
  assert.match(vars, /proxy/)
  assert.doesNotMatch(vars, /TURN_KEY_ID/, 'ni la de scope se cuela aquí')
})

test('la lista de dispositivos avisa cuántas variables propias tiene cada uno', () => {
  const term = fakeTerm(110, 24)
  V.render(term, baseState({
    screen: 'devices',
    members: [{ pub: 'PUB2', id: 'EF56-7890', label: 'proxy de casa', caps: ['secrets'], cn: 'proxy' }],
    devices: { issued: [{ sub: 'PUB2', deviceId: 'EF56-7890', label: 'proxy de casa', scope: ['vault:secrets:proxy'], exp: Date.now() + 8.64e7, nonce: 'n2' }], revoked: [] },
    secrets: { ns: {}, dev: [{ pub: 'PUB2', id: 'EF56-7890', label: '', cn: 'proxy', orphan: false, keys: [{ key: 'PORT', public: false }, { key: 'PUBLIC_URL', public: false }] }] }
  }))
  assert.match(term.last.join('\n'), /vars:2/)
})

test('arrancar con la bóveda activa CERRADA: se carga la lista y no se pide su contenido', async () => {
  // La regresión, en la función donde ocurrió. Antes se pedía el volcado de la activa
  // ANTES que la lista: la petición fallaba con «bloqueada», se salía por el error, y
  // `st.profiles` se quedaba en null → pantalla de entrada vacía.
  const bovedas = {
    current: 'p1',
    profiles: [
      { id: 'p1', name: 'Dotrino', protected: true, locked: true, current: true, fingerprint: 'fp1' },
      { id: 'p2', name: 'Trabajo', protected: false, locked: false, current: false, fingerprint: 'fp2' }
    ]
  }
  let pidioContenido = false
  const api = {
    listProfiles: async () => bovedas,
    snapshot: async () => { pidioContenido = true; throw Object.assign(new Error('profile locked'), { code: 'PROFILE_LOCKED' }) },
    deviceIdOf: async () => 'AB12-CD34'
  }
  const st = baseState({ profiles: null, devices: { issued: [{ deviceId: 'VIEJO' }], revoked: [] }, secrets: { ns: { viejo: [] }, dev: [] } })

  await V.refreshAll(fakeTerm(80, 24), st, api)

  assert.deepEqual(st.profiles, bovedas, 'la lista de bóvedas se carga igual')
  assert.equal(pidioContenido, false, 'y ni se pide lo de la cerrada')
  assert.equal(st.devices, null, 'lo que hubiera cargado se suelta, no se queda en pantalla')
  assert.equal(st.secrets, null)
  assert.equal(st.flash, null, 'mirar una bóveda cerrada desde fuera no es un error')

  // Abierta, todo lo demás sigue igual que siempre.
  bovedas.profiles[0].locked = false
  api.snapshot = async () => ({
    profiles: bovedas,
    devices: { issued: [{ sub: 'PUB1', nonce: 'n1' }], revoked: [] },
    secrets: { ns: { proxy: [{ key: 'K', public: false }] }, dev: [] },
    acta: { members: [{ pub: 'PUB1', id: 'AB12-CD34', caps: ['sign'] }] }
  })
  await V.refreshAll(fakeTerm(80, 24), st, api)
  assert.equal(st.devices.issued.length, 1)
  assert.deepEqual(st.secrets.ns.proxy, [{ key: 'K', public: false }])
  assert.equal(st.members.length, 1)
})

test('una bóveda CERRADA no te deja fuera del vault: la lista se sigue viendo', () => {
  // El candado es POR BÓVEDA. Que la activa esté cerrada no puede vaciar la pantalla de
  // entrada: si no, una contraseña te deja fuera del vault entero y sin forma de entrar a
  // las otras. (Era exactamente el fallo: se pedía el volcado de la activa ANTES que la
  // lista, y al fallar se salía sin llegar a guardarla.)
  const term = fakeTerm(90, 24)
  const st = baseState({
    screen: 'profiles',
    profiles: {
      current: 'p1',
      profiles: [
        { id: 'p1', name: 'Dotrino', protected: true, locked: true, current: true, fingerprint: 'fp1' },
        { id: 'p2', name: 'Trabajo', protected: false, locked: false, current: false, fingerprint: 'fp2' }
      ]
    },
    devices: null,
    secrets: null,
    members: []
  })

  assert.equal(V.activeLocked(st), true, 'se sabe que la activa está cerrada…')
  V.render(term, st)
  const out = term.last.join('\n')
  assert.match(out, /Dotrino/, '…y aun así sale en la lista')
  assert.match(out, /Trabajo/, 'y las demás también, para poder entrar a ellas')
  assert.match(out, /🔒/, 'con su candado a la vista')

  // Sin contraseña, o abierta, no hay candado que valga.
  st.profiles.profiles[0].locked = false
  assert.equal(V.activeLocked(st), false)
  st.profiles.profiles[0].protected = false
  assert.equal(V.activeLocked(st), false)
})

test('Perfil: muestra lo que sincronizó el aparato, y NUNCA los bytes de la foto', () => {
  const t = makeTheme()
  const me = {
    nickname: 'Seyacat',
    avatar: { type: 'image/jpeg', bytes: 8000 },
    nombres: 'Santiago',
    email: 'sandrade@dotrino.com',
    telefono: '0999', telefonoVisible: false,
    links: [{ id: '1', type: 'github', value: 'seyacat', visible: true }],
    updatedAt: Date.now()
  }
  const texto = V.meRows(baseState({ screen: 'me', me }), t).map((r) => r.text).join('\n')
  assert.match(texto, /Seyacat/)
  assert.match(texto, /image\/jpeg/)
  assert.match(texto, /7\.8 KB/, 'el tamaño en KB, no en bytes crudos')
  assert.match(texto, /sandrade@dotrino\.com/)
  assert.match(texto, /0999/)
  assert.match(texto, /oculto/, 'lo que el usuario marcó como oculto se dice')
  assert.match(texto, /github/)
  assert.ok(!texto.includes('base64'), 'la foto se resume, no se vuelca')
})

test('Perfil vacío: lo dice y explica qué hacer, sin reventar', () => {
  const t = makeTheme()
  for (const me of [null, undefined]) {
    const texto = V.meRows(baseState({ screen: 'me', me }), t).map((r) => r.text).join('\n')
    assert.ok(texto.length > 0, 'siempre dibuja algo')
  }
  const vacio = V.meRows(baseState({ screen: 'me', me: null }), t).map((r) => r.text).join('\n')
  assert.match(vacio, /perfil/i)
})


test('Permisos: los cuatro, en cristiano, con su marca — y admin destacado', () => {
  const t = makeTheme()
  const st = baseState({
    screen: 'caps',
    capsFor: { pub: 'PUB1', deviceId: 'AB12-CD34' },
    members: [{ pub: 'PUB1', id: 'AB12-CD34', label: 'móvil', caps: ['sign', 'read'] }]
  })
  const texto = V.capsRows(st, t).map((r) => r.text).join('\n')
  assert.match(texto, /AB12-CD34/)
  assert.match(texto, /\[x\].*Firmar/, 'lo que tiene va marcado')
  assert.match(texto, /\[ \].*Administrar/, 'lo que no tiene, sin marcar')
  assert.match(texto, /sin venir aquí/, 'y se explica qué implica administrar')
  // Nada de argot: la pantalla la lee alguien que no sabe qué es un scope (§9.1).
  assert.ok(!/vault:|scope|cert/i.test(texto), 'sin jerga: ' + texto)
  // Se puede elegir cada permiso.
  assert.equal(V.capsRows(st, t).filter((r) => r.sel).length, 4)
})

/**
 * EL DISPOSITIVO FANTASMA, en la pantalla del PC.
 *
 * La lista sale del ACTA, no de los certificados. Un miembro al que le retiraron el papel
 * pero no lo sacaron del acta no aparecía aquí —solo en la del navegador—, así que desde el
 * PC no se veía que existiera y no había forma de quitarlo salvo adivinar su ID para el
 * `revoke` de la línea de comandos.
 */
test('Dispositivos: un miembro SIN certificado sale igual, marcado, y se puede quitar', () => {
  const t = makeTheme()
  const members = [
    { pub: 'PUB-MASTER', id: '6729-403E', label: '', isMaster: true, caps: ['sign'] },
    { pub: 'PUB-GHOST', id: '9E32-02BC', label: 'Mac1', caps: ['sign', 'read'] },
    { pub: 'PUB-OK', id: 'C8AA-7DCF', label: 'Mac1', caps: ['sign', 'read'] }
  ]
  const st = baseState({
    screen: 'devices',
    members,
    devices: {
      issued: [{ sub: 'PUB-OK', deviceId: 'C8AA-7DCF', label: 'Mac1', scope: ['vault:sign'], exp: Date.now() + 8.64e7, nonce: 'n1' }],
      revoked: [{ nonce: 'n0' }]
    }
  })
  const rows = V.deviceRows(st, t)
  const texto = rows.map((r) => r.text).join('\n')

  assert.match(texto, /9E32-02BC/, 'el fantasma se ve')
  assert.match(texto, /SIN ACCESO/, 'y se dice que no puede entrar')
  assert.match(texto, /C8AA-7DCF/, 'el que sí tiene papel también')

  // Y se puede seleccionar para quitarlo: sin `sub` la tecla de quitar no hace nada.
  const ghost = rows.find((r) => r.sel && r.meta?.deviceId === '9E32-02BC')
  assert.ok(ghost, 'la fila es seleccionable')
  assert.equal(ghost.meta.sub, 'PUB-GHOST', 'y lleva la llave, que es por lo que se quita')

  // El master es la bóveda: ni «sin acceso» (no necesita papel) ni quitable.
  const master = rows.find((r) => r.meta?.deviceId === '6729-403E')
  assert.equal(master.meta.noAccess, false)
  assert.equal(master.meta.isMaster, true)
})

test('Dispositivos: sin acta todavía, se cae a los certificados y no se queda en blanco', () => {
  const t = makeTheme()
  const st = baseState({
    screen: 'devices',
    members: [],
    devices: { issued: [{ sub: 'PUB-OK', deviceId: 'C8AA-7DCF', label: 'Mac1', scope: ['vault:sign'], exp: null, nonce: 'n1' }], revoked: [] }
  })
  assert.match(V.deviceRows(st, t).map((r) => r.text).join('\n'), /C8AA-7DCF/)
})

test('Permisos de un aparato que ya no está en el acta: lo dice y no revienta', () => {
  const t = makeTheme()
  const st = baseState({ screen: 'caps', capsFor: { pub: 'FUERA', deviceId: 'ZZ99-YY88' }, members: [] })
  assert.ok(V.capsRows(st, t).map((r) => r.text).join('').length > 0)
})

test('la contraseña vale para TODA la sesión: si el daemon pierde el candado, no se vuelve a pedir', async () => {
  // La regresión: el estado «abierta» vive en la MEMORIA DEL DAEMON, así que un
  // `systemctl restart` (o una petición perdida) la dejaba cerrada otra vez a mitad de
  // sesión y la TUI volvía a pedir la contraseña. Tecleada una vez, vale hasta el
  // candado (`k`) o hasta salir.
  const boveda = { id: 'p1', name: 'Dotrino', protected: true, locked: true, current: true, fingerprint: 'fp1' }
  const lista = { current: 'p1', profiles: [boveda] }
  let unlocks = 0
  const api = {
    listProfiles: async () => lista,
    unlockProfile: async (id, pwd) => {
      unlocks++
      if (pwd !== 'buena') throw Object.assign(new Error('wrong password'), { code: 'WRONG_PASSWORD' })
      boveda.locked = false
      return lista
    }
  }
  const st = baseState({ profiles: lista, unlockedHere: new Set(), sessionPwd: new Map() })
  const term = fakeTerm(90, 24)

  // 1) La primera vez SÍ se pide: queda el campo abierto esperando.
  let entradas = 0
  await V.ensureUnlocked(term, st, boveda, () => { entradas++ }, null, api)
  assert.ok(st.input, 'la primera vez pide la contraseña')
  assert.equal(entradas, 0)
  await st.input.onSubmit('buena')
  assert.equal(entradas, 1, 'con la contraseña buena, sigue adelante')
  assert.equal(st.sessionPwd.get('p1'), 'buena', 'y se la queda para esta sesión')
  assert.ok(st.unlockedHere.has('p1'), 'para volver a cerrarla al salir')

  // 2) El daemon pierde el candado (reinicio del servicio): vuelve a decir «cerrada».
  boveda.locked = true
  st.input = null
  await V.ensureUnlocked(term, st, boveda, () => { entradas++ }, null, api)
  assert.equal(st.input, null, 'NO se vuelve a preguntar')
  assert.equal(entradas, 2, 'se entra igual')
  assert.equal(boveda.locked, false, 'porque se reabrió sola con la de la sesión')
  assert.equal(unlocks, 2)

  // 3) Si la contraseña guardada ya no vale, se pregunta (y se olvida la vieja).
  boveda.locked = true
  st.sessionPwd.set('p1', 'vieja')
  await V.ensureUnlocked(term, st, boveda, () => { entradas++ }, null, api)
  assert.ok(st.input, 'vuelve a preguntar')
  assert.equal(st.sessionPwd.has('p1'), false, 'y no se queda con una que ya no sirve')
})
