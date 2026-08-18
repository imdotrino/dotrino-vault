/**
 * El SELLADOR: lo único de los secretos que toca criptografía.
 *
 * `secretsStore.js` guarda la forma y las reglas y no sabe cifrar; le inyecta este
 * puerto y le pide sobres. Así el store se prueba con un sellador falso y este archivo
 * se lee entero de una sentada.
 *
 * QUÉ HACE. Cada cajón (un namespace, o el cajón propio de un aparato) tiene una CEK
 * AES-256-GCM. Las variables privadas se cifran con ella. La CEK viaja de dos formas,
 * y esa dualidad es todo el diseño:
 *
 *   · **hacia los miembros** — envuelta a la llave de cifrado (`encPub`) de cada
 *     aparato que deba leer ese cajón, con ECDH efímero: quien abre solo necesita su
 *     propia privada. Es lo que va en el llavero del archivo y lo que viaja al agente.
 *   · **hacia quien administra** — en la COPIA MAESTRA, cifrada con la llave derivada
 *     de la contraseña del perfil. Es lo que permite sellar una variable nueva o
 *     re-envolver la CEK a un aparato que entra.
 *
 * Y hay una tercera forma que NO existe a propósito: **la CEK nunca se envuelve a la
 * llave de esta bóveda**. Si se hiciera, el daemon podría abrir todo por su cuenta y
 * esto no valdría nada — que es exactamente la situación de la que venimos.
 *
 * La contraseña no está en el disco, así que una copia del disco no abre las privadas.
 * Lo que sí abre es todo lo demás; los límites honestos están en
 * `docs/secretos-sellados.md` §3 y conviene leerlos antes de confiar de más.
 */
import crypto from 'node:crypto'
import {
  makeContentKey, makeGeneration, encryptWithCek, decryptWithCek
} from '@dotrino/identity/content'

const b64 = (b) => Buffer.from(b).toString('base64')
const un64 = (s) => Buffer.from(s, 'base64')

/** La copia maestra va cifrada con AES-256-GCM bajo la llave derivada de la contraseña. */
const MASTER_V = 1

/** Se pidió abrir la copia maestra sin llave, o con la equivocada. */
export class WrongPassword extends Error {
  constructor (msg = 'wrong password') {
    super(msg)
    this.code = 'WRONG_PASSWORD'
  }
}

function assertKey (adminKey) {
  if (!(adminKey instanceof Uint8Array) || adminKey.length !== 32) {
    throw new WrongPassword('the derived key is missing or malformed (32 bytes expected)')
  }
}

/**
 * Crea el sellador. No guarda estado ni recuerda la contraseña: cada operación recibe
 * la llave derivada y la suelta. Que no se cachee es la mitad del valor de todo esto —
 * una llave que se queda en memoria para siempre deja el disco protegido y la máquina
 * igual de expuesta que antes.
 */
export function makeSealer () {
  return {
    /**
     * Abre la copia maestra: `{ "ns:<ns>": cek, "dev:<pub>": cek }`. Un `blob` vacío
     * devuelve un mapa vacío — es el primer arranque, no un error.
     */
    async openMaster (blob, adminKey) {
      assertKey(adminKey)
      if (!blob) return {}
      if (blob.v !== MASTER_V) throw new Error(`master copy: unknown format v${blob.v}`)
      try {
        const d = crypto.createDecipheriv('aes-256-gcm', adminKey, un64(blob.iv))
        d.setAuthTag(un64(blob.tag))
        return JSON.parse(Buffer.concat([d.update(un64(blob.ct)), d.final()]).toString('utf8'))
      } catch (_) {
        // El tag de AES-GCM ES el verificador: si no cuadra, la contraseña no era.
        // Por eso no hace falta guardar aparte un verificador de la contraseña, que
        // sería un camino más barato para atacarla desde una copia del disco.
        throw new WrongPassword()
      }
    },

    async sealMaster (obj, adminKey) {
      assertKey(adminKey)
      const iv = crypto.randomBytes(12)
      const c = crypto.createCipheriv('aes-256-gcm', adminKey, iv)
      const ct = Buffer.concat([c.update(JSON.stringify(obj), 'utf8'), c.final()])
      return { v: MASTER_V, iv: b64(iv), ct: b64(ct), tag: b64(c.getAuthTag()) }
    },

    /** La CEK de un cajón, creándola si es la primera variable que entra ahí. */
    async cekFor (master, owner) {
      if (!master[owner]) master[owner] = await makeContentKey()
      return master[owner]
    },

    /** Una CEK NUEVA para el cajón, tirando la anterior. Rotar es esto. */
    async newCek (master, owner) {
      master[owner] = await makeContentKey()
      return master[owner]
    },

    /** Cifra un valor con la CEK del cajón. */
    async encrypt (cek, plaintext) {
      const { iv, ct } = await encryptWithCek({ cek, gen: 0, plaintext })
      return { iv, ct }
    },

    /** Descifra con la CEK que corresponda al cajón. Solo lo usa quien administra. */
    async decrypt (master, envelope, owner) {
      const cek = master[owner]
      if (!cek) throw new Error(`master copy: no key for drawer ${owner}`)
      return decryptWithCek({ cek, envelope })
    },

    /**
     * Envuelve la CEK a cada miembro. Los que no tengan llave de cifrado salen en
     * `sinLlave` en vez de reventar: quien administra tiene que poder VERLO, porque el
     * síntoma sería un servicio arrancando sin configuración y sin decir por qué.
     */
    async wrapFor (cek, members) {
      const { generation, sinLlave } = await makeGeneration({ members, cek })
      return { wraps: generation.wraps, sinLlave }
    }
  }
}

export default { makeSealer, WrongPassword }
