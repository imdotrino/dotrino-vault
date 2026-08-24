#!/usr/bin/env node
// @dotrino/env — el mismo `dotrino-env` de @dotrino/vault, con nombre propio para poder
// llamarlo corto: `npx -y @dotrino/env enroll --ns miapp --code <código>`. Todo el código
// vive en @dotrino/vault (cliente y bóveda comparten protocolo); esto solo lo re-lanza.
import '@dotrino/vault/bin/dotrino-env.js'
