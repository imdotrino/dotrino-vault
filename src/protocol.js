/**
 * Protocolo de mensajes entre un dispositivo y el vault (viajan por el proxy,
 * direccionados por pubkey con `sendByPubkey`). El cuerpo va JSON-serializado en
 * el campo `message` del sobre del proxy; el cliente lo entrega ya parseado.
 *
 * Toda la autorización se hace con la CADENA de delegación de `@dotrino/identity`
 * (`verifyChain`): el dispositivo firma con su sub-clave `D` y adjunta el `cert`
 * que la maestra `P` le emitió. La maestra NUNCA sale del vault.
 */
export const MSG = Object.freeze({
  ENROLL: 'vault.enroll',     // dispositivo → vault: { dpub, token, label }
  ENROLLED: 'vault.enrolled', // vault → dispositivo: { cert, iss }
  SIGN: 'vault.sign',         // dispositivo → vault: { data, signature, cert }   (data.payload = lo a firmar)
  SIGNED: 'vault.signed',     // vault → dispositivo: { signature, publickey, device }
  GET: 'vault.get',           // dispositivo → vault: { data, signature, cert }   (data.id = nodo del árbol)
  DATA: 'vault.data',         // vault → dispositivo: { id, node }
  ERROR: 'vault.error'        // vault → dispositivo: { error }
})

/** Capacidades que puede llevar un `cert` (scope). */
export const SCOPE = Object.freeze({
  SIGN: 'vault:sign',  // pedir a la maestra que firme datos
  READ: 'vault:read'   // leer nodos del árbol de contenidos
})
