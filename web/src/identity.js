/**
 * Con qué iframe de identidad habla la página. En producción, el de siempre
 * (`id.dotrino.com`); en localhost, el de `/id/` que sirve vite (con el proxy-client al
 * día), o el que diga `?vault=`. Lo usan la consola y la bóveda en la nube.
 *
 * `?vault=` solo se acepta si esta página se está sirviendo desde localhost. Es importante:
 * sin ese cerrojo, un enlace del tipo `vault.dotrino.com/vault?vault=…` podría apuntar tu
 * identidad a un iframe ajeno, que es exactamente el ataque que este proyecto evita.
 */
export function identityOptions () {
  const local = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname)
  if (!local) return {}
  const url = new URLSearchParams(location.search).get('vault') || `${location.origin}/id/`
  return { vaultUrl: url }
}
