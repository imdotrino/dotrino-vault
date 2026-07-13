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
  STORE: 'vault.store',                       // dispositivo → vault: { data:{method,args,publickey,ts}, signature, cert }
  STORE_RESULT: 'vault.store.result',         // vault → dispositivo: { method, result }
  DEVICES: 'vault.devices',                   // dispositivo → vault: { data:{publickey,ts}, signature, cert }
  DEVICES_RESULT: 'vault.devices.result',     // vault → dispositivo: { devices, revoked }
  RENEW: 'vault.renew',                       // dispositivo → vault: { data:{op,publickey,ts}, signature, cert }
  RENEWED: 'vault.renewed',                   // vault → dispositivo: { cert }  (cert fresco, misma sub-clave/scope)
  SECRETS: 'vault.secrets',                   // servicio → vault: { data:{op,ns,ek,publickey,ts}, signature, cert }
  SECRETS_RESULT: 'vault.secrets.result',     // vault → servicio: { body:{op,ns,enc,ts}, signature } (enc SELLADO a ek; body firmado por la maestra)
  ERROR: 'vault.error'                        // vault → dispositivo: { error }
})

/** Capacidades que puede llevar un `cert` (scope). Mínimo por defecto. */
export const SCOPE = Object.freeze({
  SIGN: 'vault:sign',   // pedir a la maestra que firme datos (identidad)
  READ: 'vault:read',   // leer nodos del árbol de contenidos
  STORE: 'vault:store'  // leer/escribir el store de hilos + aperturas del usuario
})

/**
 * Scope de SECRETOS por namespace de servicio: un cert con `vault:secrets:proxy`
 * solo puede leer los secretos del ns `proxy` — un VPS comprometido no puede
 * pedir los de otro servicio. ns válido: [a-z0-9-]{1,32}.
 */
export const SECRETS_SCOPE_PREFIX = 'vault:secrets:'
export const secretsScope = (ns) => SECRETS_SCOPE_PREFIX + ns
export const isValidSecretsNs = (ns) => typeof ns === 'string' && /^[a-z0-9-]{1,32}$/.test(ns)
