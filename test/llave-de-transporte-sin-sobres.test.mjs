/**
 * LA LLAVE QUE FIRMA EL TRANSPORTE NO RECIBE SOBRES. NUNCA.
 *
 * Regla del dueño (2026-08-30), y es la que hace posible el multivault: la llave de
 * sellado firma las respuestas —y por eso puede vivir en una bóveda que no es la
 * principal— pero **no puede abrir nada**. Si algún día se le envolviera una CEK,
 * repartir la capacidad de servir repartiría también la de leer, y todo el reparto de
 * roles se vendría abajo sin que nadie lo notara.
 *
 * La garantía es ESTRUCTURAL, no una comprobación en tiempo de ejecución. En el acta hay
 * dos sitios distintos y no se tocan:
 *
 *   · `members[]`   → a QUIÉN se le envuelven los sobres (`recipientsOf` sale de aquí)
 *   · `sealPub` / `sealKeys[]` → QUÉ llave firma (`sealKeyAt` sale de aquí)
 *
 * Lo que no se crea no se puede saltar: si la llave de sellado no está en `members`, no
 * hay camino por el que le llegue un sobre.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { CAPS, sealKeyAt } from '@dotrino/identity/acta'

/** Un acta mínima con las dos zonas pobladas por llaves distintas. */
const acta = {
  v: 1,
  seq: 5,
  sealSince: 4,
  sealPub: 'LLAVE-DE-SELLADO',
  sealKeys: [{ pub: 'LLAVE-DE-SELLADO-VIEJA', from: 1, to: 3 }],
  members: [
    { pub: 'APARATO-DEL-DUENO', encPub: 'e1', cn: null, caps: ['sign', 'read', 'store'] },
    { pub: 'SERVICIO-PROXY', encPub: 'e2', cn: 'proxy', caps: ['secrets'] }
  ]
}

test('quien firma no está entre quienes reciben', () => {
  const miembros = acta.members.map((m) => m.pub)
  assert.ok(!miembros.includes(acta.sealPub), 'la llave de sellado no puede ser miembro')
  for (const k of acta.sealKeys) {
    assert.ok(!miembros.includes(k.pub), 'ninguna llave de sellado anterior puede ser miembro')
  }
})

test('sealKeyAt devuelve llaves de sellado y JAMÁS un miembro', () => {
  assert.equal(sealKeyAt(acta, 5), 'LLAVE-DE-SELLADO')
  assert.equal(sealKeyAt(acta, 4), 'LLAVE-DE-SELLADO')
  assert.equal(sealKeyAt(acta, 2), 'LLAVE-DE-SELLADO-VIEJA', 'un sobre viejo se comprueba con la que mandaba entonces')

  const miembros = new Set(acta.members.map((m) => m.pub))
  for (let seq = 1; seq <= acta.seq; seq++) {
    const k = sealKeyAt(acta, seq)
    assert.ok(!miembros.has(k), `#${seq}: la llave que firma no puede ser un destinatario`)
  }
})

/**
 * DOS COSAS QUE AHORA SE LLAMAN CASI IGUAL, y conviene no confundirlas nunca:
 *
 *   · el permiso **`sealer`** (2026-08-30) = SELLAR EL ACTA. Lo tiene la otra bóveda, va
 *     en el acta como cualquier permiso, y quien lo tiene **sí** recibe sobres — tiene que
 *     poder regenerarlos, para eso existe.
 *   · la llave **`sealPub`** = FIRMAR EL TRANSPORTE Y LOS SOBRES. No es un miembro, no es
 *     un permiso y **no recibe nada**.
 *
 * Lo que esta prueba fija es la segunda: que no aparezca una capacidad de miembro que
 * conceda firmar el transporte. Si la hubiera, se podría pedir «déjame firmar respuestas»
 * y llevarse de paso los sobres que recibe un miembro.
 *
 * La lista literal es a propósito: si alguien añade una capacidad al pilar, esto se cae y
 * obliga a mirar en cuál de las dos columnas acaba de meterla.
 */
test('ninguna capacidad de miembro concede firmar el TRANSPORTE', () => {
  assert.deepEqual([...CAPS].sort(), ['admin', 'approve', 'passwords', 'read', 'sealer', 'secrets', 'sign', 'store'])
  for (const c of ['seal', 'transport', 'serve', 'replica']) {
    assert.ok(!CAPS.includes(c), `«${c}» no puede ser una capacidad de miembro: firmar el transporte no es leer`)
  }
  // Y `sealer`, que sí está, es sellar el ACTA — no la llave que firma las respuestas.
  assert.ok(CAPS.includes('sealer'))
})
