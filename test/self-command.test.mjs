/**
 * Volver a lanzar la TUI tras actualizar: en el binario (SEA) `argv[1]` es otra vez el
 * ejecutable, y pasárselo como argumento arrancaba el daemon en la terminal (2026-10-16).
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { selfCommand } from '../src/service.js'

test('SEA: relaunch skips the duplicated executable path', () => {
  const { args } = selfCommand(['/x/dotrino-vaultd', '/x/dotrino-vaultd', '--ctl', 'tui'], true)
  assert.deepEqual(args, ['--ctl', 'tui'])
})

test('node: relaunch keeps the script path', () => {
  const { args } = selfCommand(['/usr/bin/node', '/x/bin/dotrino-vault.js', 'tui'], false)
  assert.deepEqual(args, ['/x/bin/dotrino-vault.js', 'tui'])
})
