/**
 * LA CONTRASEÑA QUE ABRE UNA BÓVEDA, preparada en el navegador (`docs/abrir-a-distancia.md`).
 *
 * El molino (scrypt) se hace AQUÍ, con los números que da la bóveda (`params`: salt, N, r, p,
 * len), y lo que viaja es la derivada sellada a la llave EFÍMERA que ella dio (`ek`): la bóveda
 * nunca ve la contraseña, y el sobre solo lo abre ella, una vez. `nonce` va DENTRO del sobre,
 * para que uno capturado no se pueda reenviar con otro.
 *
 * Lo usan la consola (abrir la bóveda desde el admin) y `/hosted` (la contraseña con la que nace
 * la bóveda alojada): la misma derivada tiene que salir en los dos sitios, o la contraseña que se
 * puso al comprar no abriría después.
 */
import { seal } from '@dotrino/vault/sealed'

export async function sealedAdminKey ({ password, params, nonce }) {
  const { scrypt } = await import('scrypt-js')
  const salt = Uint8Array.from(atob(params.salt), (c) => c.charCodeAt(0))
  const key = await scrypt(new TextEncoder().encode(password), salt, params.N, params.r, params.p, params.len)
  try {
    return await seal({ ek: params.ek, payload: { nonce, key: btoa(String.fromCharCode(...key)) } })
  } finally { key.fill(0) }
}

export default { sealedAdminKey }
