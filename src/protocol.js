/**
 * Protocolo de mensajes entre un dispositivo y el vault (viajan por el proxy,
 * direccionados por pubkey con `sendByPubkey`). El cuerpo va JSON-serializado en
 * el campo `message` del sobre del proxy; el cliente lo entrega ya parseado.
 *
 * Emparejamiento ENDURECIDO (ver dotrino-vault/docs/pairing-protocol.md):
 *   1. dispositivo → vault   ENROLL { data:{op,dpub,token,sn,label,ts}, signature }
 *      (la firma es del dispositivo con su llave D = PRUEBA DE POSESION; un token
 *       robado ya NO basta para enrolar).
 *   2. vault → dispositivo   ENROLL_CHALLENGE { deviceId, sas }   (aun NO firma cert)
 *   3. el dueño compara el SAS (pantalla del dispositivo ↔ del PC) y APRUEBA en el PC
 *   4. vault → dispositivo   ENROLLED { cert, iss, sas }   (recien aqui firma el cert)
 *   5. el dispositivo VALIDA la cadena: cert.iss === el iss que vio, cert.sub === D.
 *
 * Revocacion (robo): el vault envia REVOKED { body, signature } FIRMADO por la
 * maestra → el dispositivo se autoborra SOLO si la firma valida contra la maestra
 * pineada (cierra el wipe-DoS; un ERROR plano jamas borra).
 */
export const MSG = Object.freeze({
  ENROLL: 'vault.enroll',                     // dispositivo → vault: { data, signature }
  ENROLL_CHALLENGE: 'vault.enroll.challenge', // vault → dispositivo: { deviceId, sas }
  ENROLLED: 'vault.enrolled',                 // vault → dispositivo (tras aprobar): { cert, iss, sas }
  REVOKED: 'vault.revoked',                   // vault → dispositivo: { body:{op,sub,nonce,iat,exp}, signature }
  SIGN: 'vault.sign',                         // dispositivo → vault: { data, signature, cert }
  SIGNED: 'vault.signed',                     // vault → dispositivo: { signature, publickey, device }
  GET: 'vault.get',                           // dispositivo → vault: { data, signature, cert }
  DATA: 'vault.data',                         // vault → dispositivo: { id, node }
  ERROR: 'vault.error'                        // vault → dispositivo: { error }
})

/** Capacidades que puede llevar un `cert` (scope). Mínimo por defecto. */
export const SCOPE = Object.freeze({
  SIGN: 'vault:sign',  // pedir a la maestra que firme datos (identidad)
  READ: 'vault:read'   // leer nodos del árbol de contenidos
})
