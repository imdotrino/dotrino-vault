/**
 * EL PRIMER ADMINISTRADOR de una bóveda en una Lambda: un usuario con contraseña.
 *
 * Una Lambda no tiene pantalla ni teclado donde emparejar el primer aparato. Así que la pila
 * de CloudFormation pide un usuario y una contraseña, y al crearse la bóveda da de alta ese
 * usuario como un aparato más del acta (`createPasswordLogin`, el mismo camino que
 * `dotrino-vault logins add`). Quien desplegó entra con `admin@AB12-CD34-EF56` —la dirección
 * sale en los Outputs de la pila— desde «Iniciar sesión» en cualquier app o terminal, y desde
 * ahí administra: puede cambiar esos permisos, añadir aparatos o quitar este usuario.
 *
 * La contraseña no la guarda la bóveda (OPAQUE): la usa para el registro y la olvida.
 */
import { createPasswordLogin, loginAddress, accountFingerprint } from '../lib/src/passwordLogins.js'

/** Lo que tiene el primer administrador. El dueño los cambia después, desde dentro. */
export const ADMIN_CAPS = ['sign', 'read', 'store', 'admin', 'approve']

/**
 * Da de alta al administrador si la bóveda todavía no tiene ningún usuario con contraseña, y
 * devuelve su dirección. Si ya lo tiene, solo la devuelve: volver a desplegar no cambia la
 * contraseña de nadie.
 *
 * @param {object} vault
 * @param {{ user: string, password: () => Promise<string> }} opts  la contraseña se pide solo si hace falta
 * @returns {Promise<{ address: string, created: boolean }>}
 */
export async function ensureAdmin (vault, { user = 'admin', password }) {
  const fp = await accountFingerprint(vault.identity)
  if (vault.listLogins().some((l) => l.user === user)) return { address: loginAddress(user, fp), created: false }
  const r = await createPasswordLogin({
    user, password: await password(), label: 'admin', caps: ADMIN_CAPS,
    begin: (req) => vault.loginRegisterBegin(req),
    finish: (req) => vault.loginRegisterFinish(req)
  })
  return { address: loginAddress(user, r.fingerprint || fp), created: true }
}

export default { ensureAdmin, ADMIN_CAPS }
