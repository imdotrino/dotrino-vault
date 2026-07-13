/**
 * Protocolo dispositivo↔vault. La fuente ÚNICA vive en la lib publicable
 * (`@dotrino/vault`, lib/src/protocol.js) para que daemon, dispositivos y
 * SERVICIOS usen exactamente las mismas constantes. Este archivo solo re-exporta.
 */
export * from '../lib/src/protocol.js'
