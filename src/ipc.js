/**
 * ipc.js — el CANAL LOCAL entre el daemon y la CLI, **cifrado en reposo**.
 *
 * El daemon y el `dotrino-vault` de tu shell no hablan por un socket: se dejan archivos
 * JSON en el directorio de datos (`state.json`, `acta.json`, `secret-request.json`…, ver
 * la cabecera de `daemon.js`). Ese contrato es cómodo y no escucha en ningún puerto, pero
 * durante meses **fue el único sitio del vault que escribía en claro**, y por ahí pasa de
 * todo:
 *
 *   · `secret-request.json`  la CONTRASEÑA del perfil y el VALOR de lo que se guarda
 *   · `secrets-list.json`    el valor recién destapado, esperando a que la CLI lo recoja
 *   · `pair.json`            la invitación de emparejamiento, que es un secreto
 *   · `acta.json`/`devices.json`  quién es miembro, con qué permisos y qué certificados
 *   · `me.json`, `profiles-list.json`  el perfil y las públicas maestras de cada uno
 *
 * Que los archivos fueran efímeros no salvaba nada: se escriben en el disco igual, y un
 * `rm` no borra lo que ya se copió. Ahora van por el MISMO cifrado en reposo que el resto
 * (`atrest.js`), que es lo correcto aquí y no un apaño: los dos extremos corren en esta
 * máquina y con este usuario, así que comparten la clave sin negociar nada.
 *
 * **Por qué no un sobre.** Un sobre se cierra contra la pública de quien va a abrirlo, y
 * el que abre esto es tu CLI, que no tiene llave propia — inventarle una la dejaría en el
 * mismo disco y al lado, que es exactamente lo que no protege de nada. El sobre es para lo
 * que VIAJA a otro; para lo que se queda en la máquina, el reposo.
 *
 * Ojo con el dir: todos estos archivos cuelgan del directorio raíz, así que la clave sale
 * de ahí (`path.dirname`). Un archivo de perfil tiene otro salt y NO se lee con esta.
 */
import path from 'node:path'
import { atRestFor } from './atrest.js'
import { readJson, writeJson } from './paths.js'

const codecOf = (file) => atRestFor(path.dirname(file))

/** Lee un archivo del canal. `fallback` si no está o no se puede abrir. */
export const ipcRead = (file, fallback = null) => readJson(file, fallback, codecOf(file))

/** Escribe un archivo del canal, cifrado y 0600 (atómico: tmp + rename). */
export const ipcWrite = (file, obj) => writeJson(file, obj, codecOf(file))

export default { ipcRead, ipcWrite }
