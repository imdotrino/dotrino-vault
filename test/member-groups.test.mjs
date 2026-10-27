// La regla de los grupos (bóvedas, aparatos, servicios) que comparten la TUI y la consola.
import test from 'node:test'
import assert from 'node:assert/strict'
import { groupMembers } from '../lib/src/core/memberGroups.js'

test('bóvedas primero —la de aquí delante, cada una con su llave de comunicación debajo—, luego aparatos y servicios', () => {
  const g = groupMembers([
    { pub: 'tel', label: 'Teléfono' },
    { pub: 'nube', isMaster: true },
    { pub: 'c-nube', cn: 'vault', vault: 'nube' },
    { pub: 'pc', isMaster: true, isMe: true },
    { pub: 'c-pc', cn: 'vault', vault: 'pc' },
    { pub: 'proxy', cn: 'proxy' }
  ])
  assert.deepEqual(g.map((x) => x.group), ['vaults', 'devices', 'services'])
  assert.deepEqual(g[0].items.map((m) => m.pub + (m.child ? '*' : '')), ['pc', 'c-pc*', 'nube', 'c-nube*'])
  assert.deepEqual(g[1].items.map((m) => m.pub), ['tel'])
  assert.deepEqual(g[2].items.map((m) => m.pub), ['proxy'])
})

test('un grupo vacío no sale', () => {
  assert.deepEqual(groupMembers([{ pub: 'pc', isMaster: true }]).map((x) => x.group), ['vaults'])
})
