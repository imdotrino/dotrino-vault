/**
 * EL MOSTRADOR LOCAL: la misma puerta, sin salir de la máquina.
 *
 * Un servicio en el mismo equipo que la bóveda daba la vuelta por `proxy.dotrino.com`:
 * salía a internet, volvía, y si el proxio tenía un mal momento el arranque se retrasaba
 * cinco segundos por nada (dueño, 2026-09-03: «estando en la misma máquina debería ser
 * inmediato»).
 *
 * Lo que esto fija son las dos propiedades que hacen que el atajo sea aceptable:
 *
 *   1. **El nombre del socket sale de la LLAVE de la bóveda.** Una máquina puede tener
 *      varias, y un servicio solo conoce la maestra que lleva pineada: así los dos lados
 *      calculan la misma ruta sin mirar ningún índice.
 *   2. **Alcanzar el socket no autoriza nada.** Es el mismo protocolo y el mismo
 *      enrutador; la puerta la sigue abriendo el certificado contra el acta. Si algún día
 *      aparece un `if` de «viene de local» en un handler, esto es lo que hay que releer.
 *
 * El camino completo —un servicio leyendo con el proxio apuntando a la nada— se prueba
 * arrancando una bóveda de verdad; aquí van las piezas que se pueden fijar sin levantarla.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import { localSocketPath, socketDir, hasLocalVault } from '../lib/src/localdesk.js'

test('el socket se nombra por la llave de la bóveda, no por el perfil', () => {
  const a = localSocketPath('5e33b2218a926510')
  const b = localSocketPath('otra-llave-distinta')
  assert.notEqual(a, b, 'dos bóvedas en la misma máquina no pueden compartir socket')
  assert.ok(a.startsWith(socketDir()), 'y vive en el dir de ejecución, no entre los datos')
  assert.ok(a.endsWith('.sock'))
})

test('un socket que no está no es un error: es el caso normal', () => {
  // La bóveda suele vivir en OTRA máquina. Que no haya socket no es un fallo que reportar,
  // es la señal de «sal por el proxio».
  assert.equal(hasLocalVault('no-existe-esta-llave'), false)
})

test('un archivo cualquiera con ese nombre NO se toma por un mostrador', () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sock-'))
  const antes = process.env.DOTRINO_VAULT_SOCKET
  process.env.DOTRINO_VAULT_SOCKET = path.join(dir, 'falso.sock')
  fs.writeFileSync(process.env.DOTRINO_VAULT_SOCKET, 'no soy un socket')
  try {
    // Se comprueba que sea un SOCKET, no que exista el nombre: si no, un archivo suelto
    // ahí dentro haría que todo servicio intentara hablarle y fallara sin entender nada.
    assert.equal(hasLocalVault('da-igual'), false)
  } finally {
    if (antes === undefined) delete process.env.DOTRINO_VAULT_SOCKET
    else process.env.DOTRINO_VAULT_SOCKET = antes
  }
})

/**
 * LO QUE NO PUEDE PASAR: que ningún handler mire de dónde vino el mensaje. El día que uno
 * lo haga, el socket deja de ser un atajo y pasa a ser una puerta de atrás.
 */
test('ningún handler decide nada por el canal de entrada', async () => {
  const src = fs.readFileSync(new URL('../src/vault.js', import.meta.url), 'utf8')
  const sospechas = src.split('\n')
    .map((l, i) => [i + 1, l])
    .filter(([, l]) => /from\s*(===|!==|\.startsWith\()\s*['"`]local/.test(l))
  assert.deepEqual(sospechas, [],
    'un handler está mirando si el mensaje vino del socket local: la autorización sale del cert y del acta, no del camino')
})

/**
 * EL DIRECTORIO ES EL CONTROL (auditoría del 2026-09-04).
 *
 * `mkdir` con `mode` no toca un directorio que YA existe, y sin `XDG_RUNTIME_DIR` —un
 * servicio de sistema, un contenedor— la ruta cae en `/tmp`, donde cualquiera puede
 * haberlo creado antes. Quien sea dueño del directorio puede borrar el socket y poner el
 * suyo: no leería nada —la respuesta va firmada por una llave que nombra el acta— pero
 * deja sin arrancar a los servicios de la máquina.
 *
 * Y el `chmod 0600` del socket llega DESPUÉS de `listen`, así que por sí solo deja una
 * rendija. Lo que la cierra es que el directorio sea nuestro y solo nuestro; si no lo es,
 * la bóveda no abre el mostrador y lo dice — los servicios salen por el proxio, que
 * funciona.
 */
test('con el directorio abierto a otros, el mostrador local no se abre', async () => {
  const fuente = fs.readFileSync(new URL('../src/vault.js', import.meta.url), 'utf8')
  const i = fuente.indexOf('function abrirMostradorLocal (')
  assert.notEqual(i, -1)
  const cuerpo = fuente.slice(i, i + 3000)

  const comprueba = cuerpo.indexOf('statSync(dir)')
  const escucha = cuerpo.indexOf('server.listen(')
  assert.notEqual(comprueba, -1, 'hay que mirar de quién es el directorio antes de escuchar')
  assert.ok(comprueba < escucha, 'se escucha antes de comprobar el directorio')
  assert.match(cuerpo, /getuid/, 'hay que comprobar que el directorio es nuestro')
  assert.match(cuerpo, /0o077/, 'y que no esté abierto a grupo ni a otros')
})
