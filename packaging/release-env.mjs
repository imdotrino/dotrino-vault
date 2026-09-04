#!/usr/bin/env node
/**
 * Publica @dotrino/env junto a @dotrino/vault, derivando su versión y su dependencia.
 *
 * POR QUÉ EXISTE: `@dotrino/env` no tiene código propio — su `bin` es un `import` de
 * cinco líneas a `@dotrino/vault/bin/dotrino-env.js`. Su versión y su rango de
 * dependencia se mantenían A MANO, y derivaron: lo publicado en npm pedía
 * `^0.33.2` mientras `lib` iba por 0.60.2. Como en semver `0.x` el caret no cruza
 * la minor, `npm i -g @dotrino/env` instalaba un cliente de veintisiete versiones
 * atrás. El síntoma no fue un fallo de instalación sino algo peor: enrolar contra
 * un vault al día devolvía `invalid cert: no-acta`, porque ese cliente es anterior
 * al acta de perfil y no sabe con qué juzgar el certificado.
 *
 * Nada de esto se arregla bumpeando el número una vez: vuelve a pasar a la próxima
 * publicación de `lib`. Se arregla quitando el número de las manos.
 *
 *   node packaging/release-env.mjs            # muestra qué haría
 *   node packaging/release-env.mjs --publish  # sincroniza y publica
 */
import { readFileSync, writeFileSync } from 'node:fs'
import { execFileSync } from 'node:child_process'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const raiz = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const rutaLib = resolve(raiz, 'lib/package.json')
const rutaEnv = resolve(raiz, 'env-pkg/package.json')
const leer = (p) => JSON.parse(readFileSync(p, 'utf8'))

const lib = leer(rutaLib)
const env = leer(rutaEnv)
const publicar = process.argv.includes('--publish')

// La versión del wrapper ES la de lib. No tiene código propio que versionar aparte,
// y así "env 0.60.2" significa exactamente "el cliente 0.60.2", sin tabla de
// equivalencias que nadie mantiene.
const versionNueva = lib.version
const rangoNuevo = `^${lib.version}`

const cambios = []
if (env.version !== versionNueva) cambios.push(`version: ${env.version} → ${versionNueva}`)
if (env.dependencies?.['@dotrino/vault'] !== rangoNuevo) {
  cambios.push(`dep @dotrino/vault: ${env.dependencies?.['@dotrino/vault']} → ${rangoNuevo}`)
}

console.log(`@dotrino/vault (lib): ${lib.version}`)
console.log(`@dotrino/env (repo):  ${env.version}, pide ${env.dependencies?.['@dotrino/vault']}`)
if (!cambios.length) console.log('\nYa están sincronizados.')
else console.log('\nCambios:\n  ' + cambios.join('\n  '))

if (!publicar) {
  console.log('\n(simulacro — usá --publish para aplicar y publicar)')
  process.exit(0)
}

if (cambios.length) {
  env.version = versionNueva
  env.dependencies = { ...env.dependencies, '@dotrino/vault': rangoNuevo }
  writeFileSync(rutaEnv, JSON.stringify(env, null, 2) + '\n')
  console.log('\nenv-pkg/package.json actualizado')
}

const npm = (args, cwd) => {
  console.log(`\n$ npm ${args.join(' ')}   (${cwd})`)
  execFileSync('npm', args, { cwd, stdio: 'inherit' })
}

/** ¿Esa versión exacta ya está en el registry? */
const yaPublicado = (nombre, version) => {
  try {
    const vs = JSON.parse(execFileSync('npm', ['view', nombre, 'versions', '--json'], { encoding: 'utf8' }))
    return (Array.isArray(vs) ? vs : [vs]).includes(version)
  } catch { return false }   // paquete nuevo, o registry caído: que lo diga npm publish
}

/**
 * Publica, salvo que esa versión ya esté. Que `lib` ya estuviera publicada NO puede
 * abortar la tanda: es justo el caso en el que el wrapper es el que falta, y hacer
 * fallar todo ahí es como se llegó a la deriva que este script viene a evitar.
 */
const publicarSiFalta = (nombre, version, cwd) => {
  if (yaPublicado(nombre, version)) {
    console.log(`\n${nombre}@${version} ya está en el registry — se salta`)
    return false
  }
  npm(['publish', '--access', 'public'], cwd)
  return true
}

// lib PRIMERO: `npm i @dotrino/env` resuelve su dependencia contra el registry, así
// que publicar el wrapper antes que el cliente deja unos minutos en los que la
// instalación falla por una versión que todavía no existe.
const subioLib = publicarSiFalta('@dotrino/vault', lib.version, resolve(raiz, 'lib'))
const subioEnv = publicarSiFalta('@dotrino/env', versionNueva, resolve(raiz, 'env-pkg'))

if (!subioLib && !subioEnv) console.log('\nNada que publicar: los dos ya están al día.')
else console.log(`\nListo — @dotrino/vault@${lib.version} y @dotrino/env@${versionNueva} están en el registry.`)
