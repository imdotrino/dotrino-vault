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
  for (const [lang, aqui, nueva, servicio] of [
    ['es', /Entrar a esta cuenta: Perfil 1/, /Estrenar una cuenta nueva/, /Conectar un servicio/],
    ['en', /Join this account: Perfil 1/, /Start a new account/, /Connect a service/]
  ]) {
    const rows = V.pairModeRows(baseState({ screen: 'pairmode', lang }), t)
    const options = rows.filter((r) => r.sel)
    assert.equal(options.length, 3, 'hoy se puede responder de tres formas')
    assert.deepEqual(options.map((r) => r.meta.mode), ['here', 'new', 'service'])
    assert.match(rows.map((r) => r.text).join('\n'), aqui)
    assert.match(rows.map((r) => r.text).join('\n'), nueva)
    // Un SERVICIO se emparejaba solo por la línea de comandos (`pair --service <ns>`):
    // la TUI te dejaba a medias y había que salirse a la terminal a terminar.
    assert.match(rows.map((r) => r.text).join('\n'), servicio)
    // La tercera (adoptar la cuenta del dispositivo) se nombra pero NO se puede elegir.
    assert.match(rows.map((r) => r.text).join('\n'), lang === 'es' ? /Adoptar la cuenta que trae/ : /Adopt the account the device brings/)
    assert.ok(!options.some((r) => r.meta.mode === 'adopt'))
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

test('un QR de SERVICIO lo dice, y el de un aparato normal no inventa un servicio', () => {
  const t = makeTheme()
  const st = baseState({ screen: 'pairing' })
  st.pairing = { url: 'https://vault.dotrino.com/d#v=AAAA', payload: '{"v":2}', b64: 'AAAA', expiresAt: Date.now() + 200000 }
  assert.ok(!V.pairingBody(st, t, 80, 20).some((l) => /SERVICIO/.test(l)), 'un aparato normal no lleva ese aviso')

  // Con servicio: se dice ANTES del QR qué papel se está entregando (no firma, no ve
  // el contenido, solo lee las variables de su ns).
  st.pairing.service = 'proxy'
  assert.match(V.pairingBody(st, t, 80, 20)[1], /SERVICIO «proxy»/)
  st.lang = 'en'
  assert.match(V.pairingBody(st, t, 80, 20)[1], /SERVICE “proxy”/)
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
  const lines = qrToString(inviteUrl(qr)).replace(/\n$/, '').split('\n')
  const width = Math.max(...lines.map((l) => l.replace(/\x1b\[[0-9;]*m/g, '').length))
  assert.ok(width <= 53, `el QR mide ${width} columnas`)
  assert.ok(lines.length <= 27, `el QR mide ${lines.length} filas`)

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
  const vaults = {
    current: 'p1',
    profiles: [
      { id: 'p1', name: 'Dotrino', protected: true, locked: true, current: true, fingerprint: 'fp1' },
      { id: 'p2', name: 'Trabajo', protected: false, locked: false, current: false, fingerprint: 'fp2' }
    ]
  }
  let askedForContent = false
  const api = {
    listProfiles: async () => vaults,
    snapshot: async () => { askedForContent = true; throw Object.assign(new Error('profile locked'), { code: 'PROFILE_LOCKED' }) },
    deviceIdOf: async () => 'AB12-CD34'
  }
  const st = baseState({ profiles: null, devices: { issued: [{ deviceId: 'VIEJO' }], revoked: [] }, secrets: { ns: { viejo: [] }, dev: [] } })

  await V.refreshAll(fakeTerm(80, 24), st, api)

  assert.deepEqual(st.profiles, vaults, 'la lista de bóvedas se carga igual')
  assert.equal(askedForContent, false, 'y ni se pide lo de la cerrada')
  assert.equal(st.devices, null, 'lo que hubiera cargado se suelta, no se queda en pantalla')
  assert.equal(st.secrets, null)
  assert.equal(st.flash, null, 'mirar una bóveda cerrada desde fuera no es un error')

  // Abierta, todo lo demás sigue igual que siempre.
  vaults.profiles[0].locked = false
  api.snapshot = async () => ({
    profiles: vaults,
    devices: { issued: [{ sub: 'PUB1', nonce: 'n1' }], revoked: [] },
    secrets: { ns: { proxy: [{ key: 'K', public: false }] }, dev: [] },
    record: { members: [{ pub: 'PUB1', id: 'AB12-CD34', caps: ['sign'] }] }
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
  const text = V.meRows(baseState({ screen: 'me', me }), t).map((r) => r.text).join('\n')
  assert.match(text, /Seyacat/)
  assert.match(text, /image\/jpeg/)
  assert.match(text, /7\.8 KB/, 'el tamaño en KB, no en bytes crudos')
  assert.match(text, /sandrade@dotrino\.com/)
  assert.match(text, /0999/)
  assert.match(text, /oculto/, 'lo que el usuario marcó como oculto se dice')
  assert.match(text, /github/)
  assert.ok(!text.includes('base64'), 'la foto se resume, no se vuelca')
})

test('Perfil vacío: lo dice y explica qué hacer, sin reventar', () => {
  const t = makeTheme()
  for (const me of [null, undefined]) {
    const text = V.meRows(baseState({ screen: 'me', me }), t).map((r) => r.text).join('\n')
    assert.ok(text.length > 0, 'siempre dibuja algo')
  }
  const empty = V.meRows(baseState({ screen: 'me', me: null }), t).map((r) => r.text).join('\n')
  assert.match(empty, /perfil/i)
})


test('Permisos: TODOS los del acta, en cristiano, con su marca — y admin destacado', () => {
  const t = makeTheme()
  const st = baseState({
    screen: 'caps',
    capsFor: { pub: 'PUB1', deviceId: 'AB12-CD34' },
    members: [{ pub: 'PUB1', id: 'AB12-CD34', label: 'móvil', caps: ['sign', 'read'] }]
  })
  const text = V.capsRows(st, t).map((r) => r.text).join('\n')
  assert.match(text, /AB12-CD34/)
  assert.match(text, /\[x\].*Entrar a las apps como tú/, 'lo que tiene va marcado')
  assert.match(text, /\[ \].*Conectar y quitar dispositivos/, 'lo que no tiene, sin marcar')
  assert.match(text, /sin venir aquí/, 'y debajo, el detalle')
  // Nada de argot: la pantalla la lee alguien que no sabe qué es un scope (§9.1).
  assert.ok(!/vault:|scope|cert/i.test(text), 'sin jerga: ' + text)
  // EL NOMBRE DICE EL ACTO, NO LA CONSECUENCIA (dueño, 2026-09-02). «Sellar el acta» y
  // «Administrar el perfil» obligaban a saberse el modelo para entender qué concedes.
  assert.ok(!/\bacta\b|\bSellar\b/i.test(text), 'los nombres no nombran el acta: ' + text)
  // Se puede elegir cada permiso, y están LOS NUEVE que el acta reconoce. Eran cinco:
  // `aprueba` y `sella` solo se podían dar por la CLI y no se veían aquí, que es la
  // pantalla que se llama «permisos»; `desatendido` era peor —una marca local de la
  // bóveda, invisible aquí y con el sentido invertido—; y `replica` entró el 2026-09-02.
  // Si el acta gana o pierde uno, esto se pone rojo a propósito.
  assert.equal(V.capsRows(st, t).filter((r) => r.sel).length, 9)
  assert.match(text, /\[ \].*Admitir aparatos sin esta bóveda/, 'sella se ve aunque esté apagado')
  assert.match(text, /Solo sirve en otra BÓVEDA/, 'y se dice dónde significa algo')
  assert.match(text, /\[ \].*Entregar tus claves con la bóveda apagada/, 'y el replicador también')
  // El que decide si un servidor se lleva tus claves solo. Verlo APAGADO es media
  // explicación: dice que hoy te lo pregunta.
  assert.match(text, /\[ \].*Llevarse claves sin pedirte permiso/, 'desatendido se ve aunque esté apagado')
  assert.match(text, /SIN preguntarte/, 'y se dice qué significa tenerlo encendido')
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
  const text = rows.map((r) => r.text).join('\n')

  assert.match(text, /9E32-02BC/, 'el fantasma se ve')
  assert.match(text, /SIN ACCESO/, 'y se dice que no puede entrar')
  assert.match(text, /C8AA-7DCF/, 'el que sí tiene papel también')

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
  const vault = { id: 'p1', name: 'Dotrino', protected: true, locked: true, current: true, fingerprint: 'fp1' }
  const list = { current: 'p1', profiles: [vault] }
  let unlocks = 0
  const api = {
    listProfiles: async () => list,
    unlockProfile: async (id, pwd) => {
      unlocks++
      if (pwd !== 'buena') throw Object.assign(new Error('wrong password'), { code: 'WRONG_PASSWORD' })
      vault.locked = false
      return list
    }
  }
  const st = baseState({ profiles: list, unlockedHere: new Set(), sessionPwd: new Map() })
  const term = fakeTerm(90, 24)

  // 1) La primera vez SÍ se pide: queda el campo abierto esperando.
  let entries = 0
  await V.ensureUnlocked(term, st, vault, () => { entries++ }, null, api)
  assert.ok(st.input, 'la primera vez pide la contraseña')
  assert.equal(entries, 0)
  await st.input.onSubmit('buena')
  assert.equal(entries, 1, 'con la contraseña buena, sigue adelante')
  assert.equal(st.sessionPwd.get('p1'), 'buena', 'y se la queda para esta sesión')
  assert.ok(st.unlockedHere.has('p1'), 'para volver a cerrarla al salir')

  // 2) El daemon pierde el candado (reinicio del servicio): vuelve a decir «cerrada».
  vault.locked = true
  st.input = null
  await V.ensureUnlocked(term, st, vault, () => { entries++ }, null, api)
  assert.equal(st.input, null, 'NO se vuelve a preguntar')
  assert.equal(entries, 2, 'se entra igual')
  assert.equal(vault.locked, false, 'porque se reabrió sola con la de la sesión')
  assert.equal(unlocks, 2)

  // 3) Si la contraseña guardada ya no vale, se pregunta (y se olvida la vieja).
  vault.locked = true
  st.sessionPwd.set('p1', 'vieja')
  await V.ensureUnlocked(term, st, vault, () => { entries++ }, null, api)
  assert.ok(st.input, 'vuelve a preguntar')
  assert.equal(st.sessionPwd.has('p1'), false, 'y no se queda con una que ya no sirve')
})

// --------------------------- bloqueo automático ------------------------------

test('cuando la bóveda se cierra sola, la TUI OLVIDA su contraseña y sale de su contenido', async () => {
  // La otra mitad del bloqueo automático. Sin esto la TUI se quedaba con la contraseña
  // en memoria y la reabría sola a la siguiente tecla (`reunlockSilently`): el candado
  // del daemon no habría cerrado nada, y la pantalla seguiría enseñando los aparatos y
  // los nombres de las variables de una bóveda ya cerrada.
  const cerrada = { id: 'p1', name: 'Perfil 1', protected: true, locked: true, current: true, fingerprint: 'fp1' }
  const api = { listProfiles: async () => ({ current: 'p1', profiles: [cerrada] }) }
  const st = baseState({
    screen: 'secrets',
    sessionPwd: new Map([['p1', 'frase-de-prueba-larga']]),
    unlockedHere: new Set(['p1']),
    devices: { issued: [{ sub: 'AAA' }], revoked: [] },
    secrets: { ns: { proxy: { TOKEN: null } }, dev: [] },
    // La foto del daemon dice que ya está cerrada (el plazo lo lleva él).
    state: { version: 'test', autoLockMs: 5 * 60 * 1000, current: 'p1', profiles: [cerrada] }
  })
  const term = fakeTerm(90, 24)

  assert.deepEqual(V.autoLockedIds(st), ['p1'])
  assert.equal(await V.forgetAutoLocked(term, st, api), true)

  assert.equal(st.sessionPwd.size, 0, 'la contraseña se olvida')
  assert.equal(st.unlockedHere.size, 0)
  assert.equal(st.screen, 'profiles', 'y se sale de lo que se estaba mirando')
  assert.equal(st.devices, null, 'sin dejar en pantalla lo de antes')
  assert.equal(st.secrets, null)
  assert.match(st.flash.text, /5 min/, 'se dice por qué, con el plazo')

  // Ya no hay nada que olvidar: no vuelve a avisar en cada vuelta del bucle.
  assert.equal(await V.forgetAutoLocked(term, st, api), false)
})

test('la TUI se despierta a tiempo para enterarse del cierre (y no antes)', () => {
  const abierta = { id: 'p1', protected: true, locked: false, current: true, until: Date.now() + 10000 }
  const st = baseState({ sessionPwd: new Map([['p1', 'x']]), unlockedHere: new Set(), state: { profiles: [abierta] } })
  const wake = V.autoLockWakeIn(st)
  assert.ok(wake > 10000 && wake < 13000, `despierta pasado el plazo, no antes: ${wake}`)

  // Sin nada abierto por esta sesión no hay por qué despertarse: el bucle se queda
  // dormido en la tecla, como siempre.
  st.sessionPwd = new Map()
  assert.equal(V.autoLockWakeIn(st), 0)
})

test('una bóveda que ESTA sesión no abrió no le hace olvidar nada', () => {
  // El candado es por bóveda: que se cierre la de trabajo no puede tocar a la personal.
  const otra = { id: 'p2', protected: true, locked: true, current: false }
  const st = baseState({
    sessionPwd: new Map([['p1', 'x']]),
    unlockedHere: new Set(['p1']),
    state: { profiles: [{ id: 'p1', protected: true, locked: false, current: true, until: Date.now() + 9000 }, otra] }
  })
  assert.deepEqual(V.autoLockedIds(st), [])
})

/**
 * CUÁNDO ENTRÓ CADA APARATO, en la lista.
 *
 * El dato venía en el acta y se perdía en `mergeMembersAndCerts`, así que la pantalla no
 * podía enseñarlo por mucho que se quisiera — se vio con tres aparatos y ninguna forma de
 * distinguirlos (dueño, 2026-08-31). Se prueban las dos mitades: que sobrevive al merge y
 * que sale pintado.
 */
test('la lista de aparatos dice desde cuándo está cada uno', () => {
  const t = makeTheme(false)
  const cuando = Date.parse('2026-08-31T12:00:00Z')
  const members = [
    { pub: 'PUB-A', id: 'AAAA-1111', label: 'CELX', caps: ['sign'], addedAt: cuando }
  ]
  const st = baseState({
    screen: 'devices',
    members,
    devices: { issued: [{ sub: 'PUB-A', deviceId: 'AAAA-1111', label: 'CELX', scope: ['vault:sign'], exp: Date.now() + 8.64e7, nonce: 'n1' }], revoked: [] }
  })

  const fusionado = V.mergeMembersAndCerts(members, st.devices.issued)
  assert.equal(fusionado[0].addedAt, cuando, 'el merge no puede tirarlo: era el fallo')

  assert.match(V.deviceRows(st, t).map((r) => r.text).join('\n'), /2026-08-31/,
    'y la fila lo enseña')
})

/**
 * TECLEAR ES USO. El candado se cierra a los 5 min de NO USARSE, pero «usar» solo contaba
 * cuando algo pedía al daemon: se podía estar media hora navegando esta pantalla y se
 * cerraba igual — o sea, 5 minutos desde que se ABRIÓ, que es lo contrario de lo que dice
 * el diseño (dueño, 2026-08-31).
 */
test('teclear estira el candado, y no una vez por tecla', () => {
  const tocados = []
  const api = { touchProfile: async (id) => { tocados.push(id); return {} } }
  const st = baseState({ state: { profiles: [{ id: 'P1', current: true, protected: true, locked: false }] } })

  V.resetToque()
  V.seguirAqui(st, api)
  V.seguirAqui(st, api)
  V.seguirAqui(st, api)
  assert.deepEqual(tocados, ['P1'], 'tres teclas seguidas avisan UNA vez: no un archivo por tecla')
})

test('sin candado que estirar, no se molesta al daemon', () => {
  const tocados = []
  const api = { touchProfile: async (id) => { tocados.push(id); return {} } }

  V.resetToque()
  V.seguirAqui(baseState({ state: { profiles: [{ id: 'P1', current: true, protected: false, locked: false }] } }), api)
  assert.deepEqual(tocados, [], 'un perfil sin contraseña no tiene plazo que estirar')

  V.resetToque()
  V.seguirAqui(baseState({ state: { profiles: [{ id: 'P1', current: true, protected: true, locked: true }] } }), api)
  assert.deepEqual(tocados, [], 'y uno ya cerrado no se mantiene abierto tecleando')
})

/**
 * EL BORRADOR: se toca, se ve lo que cambia, y se firma UNA VEZ.
 *
 * Antes cada Enter sellaba un acta. Cambiar cuatro permisos eran cuatro actas, cuatro
 * avisos a todos los aparatos y cuatro renovaciones — y la cuenta pasaba por estados
 * intermedios que nadie quiso (un aparato con `admin` pero todavía sin `read`).
 */
test('Permisos: Enter mueve un BORRADOR y no firma nada', async () => {
  const t = makeTheme()
  const st = baseState({
    screen: 'caps',
    capsFor: { pub: 'PUB1', deviceId: 'AB12-CD34' },
    members: [{ pub: 'PUB1', id: 'AB12-CD34', label: 'móvil', caps: ['sign', 'read'] }]
  })
  const enter = { name: 'enter' }
  // Se marca «guarda» (que no tenía) y se desmarca «firma» (que sí).
  st.sel.caps = 1                                    // store
  await V.onKeyCaps({ t }, st, enter)
  st.sel.caps = 0                                    // sign
  await V.onKeyCaps({ t }, st, enter)

  assert.deepEqual([...st.capsDraft.caps].sort(), ['read', 'store'], 'el borrador se movió')
  assert.deepEqual(st.members[0].caps, ['sign', 'read'], 'y el acta NO: no se firmó nada')

  const text = V.capsRows(st, t).map((r) => r.text).join('\n')
  assert.match(text, /\*/, 'lo que cambia va marcado')
  assert.match(text, /2 cambio\(s\) sin guardar/, 'y se dice cuántos, para no firmar a ciegas')
})

test('Permisos: salir con cambios sin guardar PREGUNTA antes de tirarlos', async () => {
  const t = makeTheme()
  const st = baseState({
    screen: 'caps',
    capsFor: { pub: 'PUB1', deviceId: 'AB12-CD34' },
    members: [{ pub: 'PUB1', id: 'AB12-CD34', label: 'móvil', caps: ['sign'] }]
  })
  st.sel.caps = 1
  await V.onKeyCaps({ t }, st, { name: 'enter' })
  await V.onKeyCaps({ t }, st, { name: 'escape' })
  assert.equal(st.screen, 'caps', 'no se sale de golpe')
  assert.ok(st.confirm, 'se pregunta')
  assert.match(st.confirm.text, /Descartar/i)

  // Y sin cambios se sale sin preguntar: confirmar por nada es ruido.
  const limpio = baseState({
    screen: 'caps',
    capsFor: { pub: 'PUB1', deviceId: 'AB12-CD34' },
    members: [{ pub: 'PUB1', id: 'AB12-CD34', label: 'móvil', caps: ['sign'] }]
  })
  await V.onKeyCaps({ t }, limpio, { name: 'escape' })
  assert.equal(limpio.screen, 'devices')
  assert.equal(limpio.confirm, null)
})

/**
 * A UN SERVICIO SE LE ENSEÑA SU CAJÓN; a un aparato tuyo, no.
 *
 * `secrets` faltaba en esta pantalla y es EL permiso de un servicio — el que decide si
 * abre su cajón. No verlo hacía creer que no existe, exactamente lo mismo que pasaba con
 * `unattended` y con `sealer`. Y a un aparato sin `cn` no se le ofrece: no hay cajón que
 * abrir, el acta lo filtra, y una casilla que no hace nada es peor que ninguna.
 */
test('Permisos: el cajón sale SOLO para un servicio, y con su nombre dentro', () => {
  const t = makeTheme()
  const servicio = baseState({
    screen: 'caps',
    capsFor: { pub: 'PUB1', deviceId: 'AB12-CD34' },
    members: [{ pub: 'PUB1', id: 'AB12-CD34', label: 'proxy1', cn: 'proxy', caps: ['secrets'] }]
  })
  const filas = V.capsRows(servicio, t)
  const texto = filas.map((r) => r.text).join('\n')
  assert.match(texto, /\[x\].*Leer las claves de «proxy»/, 'se ve, marcado, y dice QUÉ cajón')
  assert.match(texto, /SU cajón y ninguno más/, 'y que no puede abrir otro')
  assert.equal(filas.filter((r) => r.sel).length, 10, 'los nueve de aparato + el suyo')
  assert.equal(filas.find((r) => r.meta?.cap === 'secrets') !== undefined, true)

  // Un aparato TUYO no tiene cajón: no se le ofrece.
  const aparato = baseState({
    screen: 'caps',
    capsFor: { pub: 'PUB2', deviceId: 'EF56-7890' },
    members: [{ pub: 'PUB2', id: 'EF56-7890', label: 'teléfono', caps: ['sign'] }]
  })
  const suyas = V.capsRows(aparato, t)
  assert.equal(suyas.filter((r) => r.sel).length, 9)
  assert.equal(suyas.find((r) => r.meta?.cap === 'secrets'), undefined, 'no hay cajón que abrir')
})

/**
 * F5 TAMPOCO TIRA EL BORRADOR CALLANDO.
 *
 * Refrescar trae el acta otra vez y el borrador se queda sin con qué compararse, así que
 * hay que descartarlo — pero descartarlo sin decirlo es perder trabajo en silencio, que es
 * justo lo que Esc dejó de hacer. Se pregunta lo mismo, y por la misma razón.
 */
test('Permisos: F5 con cambios sin guardar PREGUNTA, igual que Esc', async () => {
  const t = makeTheme()
  const st = baseState({
    screen: 'caps',
    capsFor: { pub: 'PUB1', deviceId: 'AB12-CD34' },
    members: [{ pub: 'PUB1', id: 'AB12-CD34', label: 'móvil', caps: ['sign'] }]
  })
  st.sel.caps = 1
  await V.onKeyCaps({ t }, st, { name: 'enter' })
  const antes = [...st.capsDraft.caps]
  await V.onKeyCaps({ t }, st, { name: 'f5' })
  assert.ok(st.confirm, 'se pregunta antes de refrescar')
  assert.match(st.confirm.text, /Descartar/i)
  assert.deepEqual([...st.capsDraft.caps], antes, 'y el borrador sigue ahí hasta que contestes')
})
