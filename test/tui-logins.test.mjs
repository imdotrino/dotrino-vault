/**
 * LA PANTALLA DE «ENTRAR CON CONTRASEÑA» DE LA TUI.
 *
 * Existe porque la regla de las tres versiones no admite lo contrario: lo que el binario
 * sabe hacer tiene que poder hacerse en SU pantalla, no solo escribiendo un comando. Y
 * además tiene que hacerlo por el MISMO canal que el CLI — dos caminos al mismo mostrador
 * se desincronizan, y entonces la pantalla enseña una cosa y el comando hace otra.
 *
 * Lo que se fija aquí:
 *
 *   · la pestaña existe y se puede llegar a ella con ←→;
 *   · dibuja sin reventar con la lista vacía, con uno bloqueado y con sesiones abiertas —
 *     que es donde se rompen las TUIs;
 *   · cada tecla llama a lo que dice, y las que no aplican AHORA no se anuncian;
 *   · y no hay ni un texto sin traducir.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import { makeTheme, trunc } from '../src/tui/term.js'
import { __test as V } from '../src/tui/app.js'
import { dict, LANGS } from '../src/tui/i18n.js'

const t = makeTheme()   // sin TTY: texto plano
const fakeTerm = (cols = 80, rows = 24) => {
  let last = []
  return { t, size: () => ({ cols, rows }), render: (l) => { last = l.map((x) => trunc(x ?? '', cols)) }, get last () { return last } }
}

const unLogin = (over = {}) => ({
  user: 'ana', address: 'ana@AB12-CD34-EF56', deviceId: 'AB12-CD34', label: 'el cyber',
  createdAt: Date.now() - 86400000, sessions: [], blockedUntil: 0, ...over
})

const estado = (over = {}) => ({
  screen: 'logins', lang: 'es', sel: { logins: 0 }, scroll: {}, logins: [], flash: null,
  input: null, confirm: null, busy: null, daemonUp: true, state: { version: 'test' },
  profiles: { current: 'p1', profiles: [{ id: 'p1', name: 'Perfil 1', current: true }] },
  devices: { issued: [], revoked: [] }, secrets: { ns: {}, dev: [] }, me: null, pending: null,
  ...over
})

test('la pestaña existe en los dos idiomas y es una de las de dentro de una bóveda', async () => {
  const src = fs.readFileSync(new URL('../src/tui/app.js', import.meta.url), 'utf8')
  const m = /const INNER_TABS = \[([^\]]*)\]/.exec(src)
  assert.ok(m, 'la TUI tiene que tener sus pestañas internas')
  const tabs = m[1].split(',').map((x) => x.trim().replace(/^'|'$/g, '')).filter(Boolean)
  assert.ok(tabs.includes('logins'), 'sin esto no se puede llegar con ←→')
  for (const lang of LANGS) assert.ok(dict(lang).tabLogins, `falta el nombre de la pestaña en ${lang}`)
})

test('dibuja vacía, y lo que dice ahí es cómo crear uno (no un hueco)', () => {
  const st = estado()
  const rows = V.loginRows(st, t)
  const texto = rows.map((r) => r.text).join('\n')
  assert.match(texto, /Todavía no hay ninguno/)
  assert.equal(rows.filter((r) => r.sel).length, 0, 'sin filas no hay nada que seleccionar')
})

test('cada fila enseña la DIRECCIÓN, que es lo que se teclea en el equipo prestado', () => {
  const rows = V.loginRows(estado({ logins: [unLogin()] }), t)
  const fila = rows.find((r) => r.sel)
  assert.ok(fila, 'la fila tiene que poder seleccionarse')
  assert.match(fila.text, /ana@AB12-CD34-EF56/)
  assert.match(fila.text, /AB12-CD34/, 'y el id del aparato, para cruzarlo con Dispositivos')
})

test('una espera por intentos fallidos SE VE, y en segundos', () => {
  const rows = V.loginRows(estado({ logins: [unLogin({ blockedUntil: Date.now() + 32_000 })] }), t)
  assert.match(rows.find((r) => r.sel).text, /espera 3[12] s/)
})

test('las sesiones abiertas se cuentan en la fila', () => {
  const rows = V.loginRows(estado({
    logins: [unLogin({ sessions: [{ sid: 'abc', lastUsedAt: Date.now() }, { sid: 'def', lastUsedAt: Date.now() }] })]
  }), t)
  assert.match(rows.find((r) => r.sel).text, /2 abiertos/)
})

test('el render entero no revienta en ningún estado, y respeta el alto', () => {
  for (const st of [
    estado(),
    estado({ logins: [unLogin(), unLogin({ user: 'luis', address: 'luis@AB12-CD34-EF56' })] }),
    estado({ logins: [unLogin({ blockedUntil: Date.now() + 90_000, sessions: [{ sid: 'x', lastUsedAt: 0 }] })] }),
    estado({ logins: null }),
    estado({ input: { label: '¿Qué nombre de usuario?', value: '', hint: 'x', mask: false } }),
    estado({ confirm: { text: '¿Quitar «ana»?' } })
  ]) {
    for (const [cols, rows] of [[80, 24], [40, 10], [200, 60]]) {
      const term = fakeTerm(cols, rows)
      assert.doesNotThrow(() => V.render(term, st))
      assert.ok(term.last.length <= rows, `se pasó del alto en ${cols}x${rows}`)
    }
  }
})

/** Un `vaultControl` de mentira: solo apunta a qué se le pidió. */
function espia (over = {}) {
  const visto = []
  const api = {
    listLogins: async () => [unLogin()],
    addLogin: async (a) => { visto.push(['add', a]); return { ok: true } },
    passwdLogin: async (a) => { visto.push(['passwd', a]); return { ok: true } },
    closeLoginSession: async (u) => { visto.push(['close', u]); return { ok: true, closed: 1 } },
    unblockLogin: async (u) => { visto.push(['unblock', u]); return { ok: true } },
    removeLogin: async (u) => { visto.push(['remove', u]); return { ok: true } },
    ...over
  }
  return { visto, api }
}

/** Teclea en el modal que haya abierto, hasta que no quede ninguno. */
async function responder (st, respuestas) {
  for (const r of respuestas) {
    assert.ok(st.input, `esperaba una pregunta para responder «${r}»`)
    const onSubmit = st.input.onSubmit
    st.input = null
    await onSubmit(r)
  }
}

test('«n» pregunta usuario, de dónde entra y la contraseña DOS VECES', async () => {
  const { visto, api } = espia()
  const st = estado()
  await V.onKeyLogins(fakeTerm(), st, { name: 'char', ch: 'n' }, api)
  await responder(st, ['Ana', 'el cyber', 'una contraseña larga', 'una contraseña larga'])
  assert.equal(visto.length, 1, 'tenía que llamar a addLogin una vez')
  const [, args] = visto[0]
  assert.equal(args.user, 'ana', 'el usuario se normaliza a minúsculas')
  assert.equal(args.label, 'el cyber')
  assert.equal(args.password, 'una contraseña larga')
})

test('una contraseña corta NO llega al daemon, y se dice por qué', async () => {
  const { visto, api } = espia()
  const st = estado()
  await V.onKeyLogins(fakeTerm(), st, { name: 'char', ch: 'n' }, api)
  await responder(st, ['ana', 'el cyber', 'corta'])
  assert.equal(visto.length, 0, 'no puede salir de aquí')
  assert.match(st.flash?.text || '', /12 caracteres/)
})

test('dos contraseñas distintas tampoco pasan', async () => {
  const { visto, api } = espia()
  const st = estado()
  await V.onKeyLogins(fakeTerm(), st, { name: 'char', ch: 'n' }, api)
  await responder(st, ['ana', 'el cyber', 'una contraseña larga', 'otra contraseña larga'])
  assert.equal(visto.length, 0)
  assert.match(st.flash?.text || '', /No coinciden/)
})

test('«x» sin sesiones abiertas no manda nada: lo dice', async () => {
  const { visto, api } = espia()
  const st = estado({ logins: [unLogin()] })
  await V.onKeyLogins(fakeTerm(), st, { name: 'char', ch: 'x' }, api)
  assert.equal(visto.length, 0)
  assert.match(st.flash?.text || '', /ninguna sesión/)
})

test('«u» sin espera tampoco', async () => {
  const { visto, api } = espia()
  const st = estado({ logins: [unLogin()] })
  await V.onKeyLogins(fakeTerm(), st, { name: 'char', ch: 'u' }, api)
  assert.equal(visto.length, 0)
  assert.match(st.flash?.text || '', /no está esperando/)
})

test('«v» PREGUNTA antes de quitar, y decir que no no quita nada', async () => {
  const { visto, api } = espia()
  const st = estado({ logins: [unLogin()] })
  await V.onKeyLogins(fakeTerm(), st, { name: 'char', ch: 'v' }, api)
  assert.ok(st.confirm, 'quitar tiene que preguntar')
  assert.match(st.confirm.text, /ana/)
  await st.confirm.onNo()
  assert.equal(visto.length, 0, 'decir que no no puede quitar nada')

  // Y decir que sí sí: es lo que hace que la pregunta signifique algo.
  await V.onKeyLogins(fakeTerm(), st, { name: 'char', ch: 'v' }, api)
  await st.confirm.onYes()
  assert.deepEqual(visto.map(([op]) => op), ['remove'])
})

test('la ayuda NO anuncia teclas que ahora no hacen nada', async () => {
  const src = fs.readFileSync(new URL('../src/tui/i18n.js', import.meta.url), 'utf8')
  assert.ok(/helpLogins:/.test(src), 'la pantalla tiene que tener su barra de ayuda')
  for (const lang of LANGS) {
    const i = dict(lang)
    const vacia = i.helpLogins({ hasLogins: false, hasSessions: false, blocked: false }).join(' ')
    const llena = i.helpLogins({ hasLogins: true, hasSessions: true, blocked: true }).join(' ')
    assert.ok(!/ c |contrase|password/i.test(vacia), `${lang}: sin ninguno, «c contraseña» no hace nada`)
    assert.ok(/ c |contrase|password/i.test(llena), `${lang}: con uno, tiene que ofrecerla`)
    assert.ok(!/ u /.test(vacia), `${lang}: sin espera, «u» no hace nada`)
    assert.ok(/ u /.test(llena), `${lang}: con espera, tiene que ofrecerla`)
  }
})

