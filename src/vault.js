/**
 * LA BÓVEDA DEL BINARIO: el núcleo compartido (`lib/src/core/vault.js`) con lo que pone
 * Node (`./platform.js`). La pestaña y la extensión corren el MISMO núcleo con la
 * plataforma del navegador, y por eso las tres bóvedas hacen lo mismo.
 */
import { startVault as startVaultCore } from '../lib/src/core/vault.js'
import { nodePlatform } from './platform.js'
import { dataDir } from './paths.js'

export async function startVault ({ dir = dataDir(), ...opts } = {}) {
  return startVaultCore({ ...opts, platform: nodePlatform(dir) })
}

export default { startVault }
