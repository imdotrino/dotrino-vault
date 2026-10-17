/**
 * LA BÓVEDA DEL BINARIO: el núcleo compartido (`lib/src/core/vault.js`) con lo que pone
 * Node (`./platform.js`). La pestaña y la extensión corren el MISMO núcleo con la
 * plataforma del navegador, y por eso las tres bóvedas hacen lo mismo.
 */
import { startVault as startVaultCore } from '../lib/src/core/vault.js'
import { nodePlatform } from './platform.js'
import { dataDir } from './paths.js'

/**
 * `platform` suma o cambia piezas de la del binario: la Lambda (`lambda/session.mjs`) pone
 * la URL que la despierta y un cliente del proxio que le dice cuándo hay trabajo.
 */
export async function startVault ({ dir = dataDir(), platform = null, ...opts } = {}) {
  return startVaultCore({ ...opts, platform: { ...nodePlatform(dir), ...(platform || {}) } })
}

export default { startVault }
