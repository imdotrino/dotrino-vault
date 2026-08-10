/**
 * i18n de la TUI: que los dos diccionarios digan LO MISMO (ninguna clave suelta ni
 * traducción olvidada), que el idioma inicial salga de donde debe y que la tecla
 * `l` conmute y lo recuerde.
 *
 * El dir de datos se apunta a un temporal ANTES de guardar nada: si no, el test
 * escribiría el `prefs.json` del usuario y le cambiaría el idioma de verdad.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { dict, otherLang, loadLang, saveLang, LANGS } from '../src/tui/i18n.js'

const tmpDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'vault-i18n-'))

/** Aísla env + dir de datos: cada caso arranca sin herencia del anterior. */
function withEnv (env, fn) {
  const keys = ['DOTRINO_VAULT_DIR', 'DOTRINO_LANG', 'LC_ALL', 'LC_MESSAGES', 'LANGUAGE', 'LANG']
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]))
  for (const k of keys) delete process.env[k]
  Object.assign(process.env, env)
  try { return fn() } finally {
    for (const k of keys) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k] }
  }
}

test('los dos diccionarios tienen exactamente las mismas claves', () => {
  const es = dict('es'); const en = dict('en')
  const only = (a, b) => Object.keys(a).filter((k) => !(k in b))
  assert.deepEqual(only(es, en), [], 'claves sin traducir al inglés')
  assert.deepEqual(only(en, es), [], 'claves que sobran en inglés')
})

test('cada entrada es del mismo tipo (y las funciones, de la misma aridad)', () => {
  const es = dict('es'); const en = dict('en')
  for (const k of Object.keys(es)) {
    assert.equal(typeof en[k], typeof es[k], `tipo distinto en "${k}"`)
    if (typeof es[k] === 'function') assert.equal(en[k].length, es[k].length, `aridad distinta en "${k}"`)
    if (Array.isArray(es[k])) assert.ok(Array.isArray(en[k]), `"${k}" debería ser lista en inglés`)
  }
})

test('ninguna traducción queda vacía', () => {
  for (const lang of LANGS) {
    const d = dict(lang)
    for (const [k, v] of Object.entries(d)) {
      if (typeof v === 'string') assert.ok(v.length, `${lang}.${k} vacío`)
      else if (Array.isArray(v)) assert.ok(v.length && v.every((s) => s.length), `${lang}.${k} con segmentos vacíos`)
      else if (typeof v === 'function') assert.ok(String(v('x', 'y')).length, `${lang}.${k} devuelve vacío`)
    }
  }
})

test('la ayuda ofrece el OTRO idioma en las dos direcciones', () => {
  assert.ok(dict('es').helpProfiles.includes('l English'))
  assert.ok(dict('en').helpProfiles.includes('l Español'))
})

test('LAS TECLAS SON LAS MISMAS EN LOS DOS IDIOMAS (mnemónico inglés)', () => {
  // La primera "palabra" de cada segmento es la tecla; solo debe cambiar el texto
  // que la explica. Si alguien traduce una tecla, este test lo caza.
  const keysOf = (segs) => segs.map((s) => s.split(' ')[0])
  // Algunas barras son FUNCIÓN del estado (solo anuncian lo que se puede hacer ahora): se
  // resuelven con todo disponible, que es el catálogo completo de esa pantalla.
  const TODO = { pendiente: true, hayAparatos: true, haySecretos: true }
  const segsOf = (d, screen) => (typeof d[screen] === 'function' ? d[screen](TODO) : d[screen])
  for (const screen of ['helpProfiles', 'helpDevices', 'helpSecrets', 'helpPairing', 'downHelp']) {
    assert.deepEqual(keysOf(segsOf(dict('en'), screen)), keysOf(segsOf(dict('es'), screen)), `teclas distintas en ${screen}`)
  }
  // Y son las inglesas: locK, pair, change-password, language… (el candado ya no es `l`).
  assert.ok(dict('es').helpProfiles.some((s) => s.startsWith('k ')), 'k = locK')
  assert.ok(dict('es').helpProfiles.some((s) => s.startsWith('c ')), 'c = change password')
  // `p` = emparejar en las DOS pantallas: una tecla, un significado.
  for (const screen of ['helpProfiles', 'helpDevices']) {
    for (const lang of ['es', 'en']) {
      const seg = segsOf(dict(lang), screen).find((s) => s.startsWith('p '))
      assert.ok(seg && /(emparejar|pair)/.test(seg), `p debería ser emparejar en ${screen}/${lang}: ${seg}`)
    }
  }
  assert.ok(dict('es').helpPairing.some((s) => s.startsWith('r ')), 'r = restart')

  // Ninguna tecla se repite dentro de la misma pantalla.
  for (const screen of ['helpProfiles', 'helpDevices', 'helpSecrets', 'helpPairing', 'downHelp']) {
    const keys = keysOf(segsOf(dict('en'), screen)).filter((k) => /^[a-zA-Z]$/.test(k)).map((k) => k.toLowerCase())
    assert.equal(new Set(keys).size, keys.length, `tecla repetida en ${screen}: ${keys}`)
  }
})

test('dict() cae al español ante cualquier valor desconocido', () => {
  assert.equal(dict('fr').code, 'es')
  assert.equal(dict(undefined).code, 'es')
  assert.equal(dict('en').code, 'en')
  assert.equal(otherLang('en'), 'es')
  assert.equal(otherLang('es'), 'en')
})

test('idioma inicial: DOTRINO_LANG manda sobre lo guardado y sobre el locale', () => {
  const dir = tmpDir()
  withEnv({ DOTRINO_VAULT_DIR: dir, DOTRINO_LANG: 'en', LANG: 'es_EC.UTF-8' }, () => {
    assert.equal(loadLang(), 'en')
  })
})

test('idioma inicial: lo guardado gana al locale del sistema', () => {
  const dir = tmpDir()
  withEnv({ DOTRINO_VAULT_DIR: dir, LANG: 'es_EC.UTF-8' }, () => {
    assert.equal(saveLang('en'), true)
    assert.equal(loadLang(), 'en')
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'prefs.json'), 'utf8')).lang, 'en')
  })
})

test('idioma inicial: sin nada guardado, lo dice el locale (y si no, español)', () => {
  withEnv({ DOTRINO_VAULT_DIR: tmpDir(), LANG: 'en_US.UTF-8' }, () => assert.equal(loadLang(), 'en'))
  withEnv({ DOTRINO_VAULT_DIR: tmpDir(), LANG: 'es_EC.UTF-8' }, () => assert.equal(loadLang(), 'es'))
  withEnv({ DOTRINO_VAULT_DIR: tmpDir(), LANG: 'C.UTF-8' }, () => assert.equal(loadLang(), 'es'))
  withEnv({ DOTRINO_VAULT_DIR: tmpDir(), LC_ALL: 'en_GB.UTF-8', LANG: 'es_EC.UTF-8' }, () => assert.equal(loadLang(), 'en'))
  withEnv({ DOTRINO_VAULT_DIR: tmpDir() }, () => assert.equal(loadLang(), 'es'))
})

test('guardar el idioma conserva las demás preferencias', () => {
  const dir = tmpDir()
  withEnv({ DOTRINO_VAULT_DIR: dir }, () => {
    fs.writeFileSync(path.join(dir, 'prefs.json'), JSON.stringify({ otra: 42 }))
    saveLang('en')
    const prefs = JSON.parse(fs.readFileSync(path.join(dir, 'prefs.json'), 'utf8'))
    assert.equal(prefs.otra, 42)
    assert.equal(prefs.lang, 'en')
  })
})

test('un idioma inválido no se guarda', () => {
  const dir = tmpDir()
  withEnv({ DOTRINO_VAULT_DIR: dir }, () => {
    assert.equal(saveLang('fr'), false)
    assert.equal(fs.existsSync(path.join(dir, 'prefs.json')), false)
  })
})

test('no poder escribir la preferencia NO rompe la TUI', () => {
  // Dir de datos inexistente y no creable (bajo un archivo): saveLang devuelve false.
  const dir = tmpDir()
  const file = path.join(dir, 'soy-un-archivo')
  fs.writeFileSync(file, 'x')
  withEnv({ DOTRINO_VAULT_DIR: path.join(file, 'sub') }, () => {
    assert.equal(saveLang('en'), false)
  })
})

test('la tecla `l` conmuta el idioma, lo recuerda y lo dice en el idioma nuevo', async () => {
  const dir = tmpDir()
  const { __test: V } = await import('../src/tui/app.js')
  withEnv({ DOTRINO_VAULT_DIR: dir }, () => {
    const st = { lang: 'es', flash: null }
    V.toggleLang(st)
    assert.equal(st.lang, 'en')
    assert.equal(st.flash.text, dict('en').langChanged)
    assert.equal(JSON.parse(fs.readFileSync(path.join(dir, 'prefs.json'), 'utf8')).lang, 'en')
    V.toggleLang(st)
    assert.equal(st.lang, 'es')
    assert.equal(st.flash.text, dict('es').langChanged)
  })
})


test('la barra solo anuncia lo que se puede hacer AHORA', () => {
  // Por SEGMENTOS y no con una regex sobre la línea entera: la tecla es la primera
  // palabra de cada segmento, y buscar `\ba ` en el texto casa con la «a» de «pestaña»
  // (la ñ no es carácter de palabra) — es justo el falso positivo que me comí.
  const teclas = (segs) => segs.map((x) => x.split(' ')[0])

  for (const lang of ['es', 'en']) {
    const d = dict(lang)
    const vacio = teclas(d.helpDevices({ pendiente: false, hayAparatos: false }))
    assert.ok(!vacio.includes('a'), 'sin nadie esperando no se ofrece aprobar: ' + vacio)
    assert.ok(!vacio.includes('x'), 'ni rechazar: ' + vacio)
    assert.ok(!vacio.includes('v'), 'sin aparatos no se ofrece revocar: ' + vacio)
    assert.ok(!vacio.includes('r'), 'ni renombrar: ' + vacio)
    assert.ok(vacio.includes('p'), 'emparejar SIEMPRE se puede')
    assert.ok(vacio.includes('F5') && vacio.includes('q'), 'refrescar y salir también')

    const conPendiente = teclas(d.helpDevices({ pendiente: true, hayAparatos: false }))
    assert.ok(conPendiente.includes('a') && conPendiente.includes('x'), 'con alguien esperando: aprobar y rechazar')
    assert.ok(!conPendiente.includes('v'), 'pero seguir sin aparatos no habilita revocar')

    const conAparatos = teclas(d.helpDevices({ pendiente: false, hayAparatos: true }))
    assert.ok(conAparatos.includes('r') && conAparatos.includes('v'), 'con aparatos: renombrar y revocar')
    assert.ok(!conAparatos.includes('a'), 'y sin pendiente sigue sin ofrecer aprobar')

    assert.ok(!teclas(d.helpSecrets({ haySecretos: false })).includes('x'), 'sin secretos no se ofrece quitar')
    assert.ok(teclas(d.helpSecrets({ haySecretos: true })).includes('x'), 'con secretos sí')
  }
})


test('`r` significa RENOMBRAR en toda la TUI (una tecla, un significado)', () => {
  for (const lang of ['es', 'en']) {
    const d = dict(lang)
    const enDispositivos = d.helpDevices({ hayAparatos: true }).find((x) => x.startsWith('r '))
    const enBovedas = d.helpProfiles.find((x) => x.startsWith('r '))
    assert.ok(/(renombrar|rename)/.test(enDispositivos), 'r = renombrar en Dispositivos: ' + enDispositivos)
    assert.ok(/(renombrar|rename)/.test(enBovedas), 'r = renombrar en Bóvedas: ' + enBovedas)
    // Y refrescar deja de comerse una letra: es F5, como en todas partes.
    for (const segs of [d.helpDevices({ hayAparatos: true }), d.helpSecrets({ haySecretos: true }), d.helpMe]) {
      const refrescar = segs.find((x) => /(refrescar|refresh)/.test(x))
      assert.ok(refrescar.startsWith('F5 '), 'refrescar es F5: ' + refrescar)
    }
  }
})
