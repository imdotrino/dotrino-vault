# Entrar — sesiones, y el inicio de sesión federado

> **Estado:** plan de diseño, **sin implementar**. Decidido con el dueño el
> 2026-09-05: se hacen las tres direcciones **en este orden** — primero entrar en un
> aparato nuevo, después "Entrar con Dotrino" en aplicaciones ajenas, y al final
> entrar a Dotrino con un proveedor externo (Microsoft/AD).
>
> Fija el *qué* y el *cómo*, y deja marcado lo que falta decidir (§9). El código va
> en inglés (`CONVENCIONES-APPS.md` §8.1); los identificadores de aquí ya lo están.

## 1. El problema: enlazar no es entrar

La bóveda tiene muchas formas de **enlazar** —`pair`, `pair --new-account`,
`pair --adopt`, `pair --service`, `--scope`, `--approval`, `join`, la invitación
`.dpair`, la cita corta, «este aparato es la bóveda», `enrollWithVault` del
`remote-agent`, las réplicas— y todas terminan en lo mismo:

> **una llave nueva metida en el acta, para siempre hasta que alguien la revoque.**

De ahí salen tres consecuencias que impiden llamar a eso *iniciar sesión*:

1. **Entrar cuesta caro.** Admitir un miembro es sellar el acta, sellar es de la
   selladora, y con el perfil cerrado la selladora no está
   ([`acta-de-perfil.md`](./acta-de-perfil.md), y la regla dura de `CLAUDE.md`:
   *la maestra tiene dos trabajos*). Hace falta la bóveda abierta, el SAS y una
   persona delante. Nadie hace eso para abrir una aplicación en un navegador
   prestado.
2. **No se puede salir.** Cerrar sesión sería revocar, que es sellar otra vez. La
   subacta no ayuda: [solo puede quitar, nunca dar](../src/subacta.js), y quitar
   exige que el afectado firme su propia renuncia.
3. **El sobre firmado no dice para quién es.** Hoy no hay `aud`, `nonce` ni `exp`:
   un sobre firmado para el proxio **vale ante geo**. La protección contra
   repetición evita el reenvío, no el cruce de destinatario. Es un agujero abierto
   hoy, no un requisito de una función futura.

Y hay un cuarto hueco, que es el que nota el usuario: **un aparato o es de la
familia o no existe**. No hay término medio para «entro aquí un rato».

## 2. Las dos entradas

Decisión del dueño: **existen las dos, y cada una tiene su caso.**

| | **Sesión** | **Aparato** |
|---|---|---|
| Para | un navegador prestado, un kiosco, «entro un rato» | tu teléfono, tu PC, un servicio |
| Qué crea | una sesión con vencimiento | un miembro del acta |
| Toca el acta | **no** | sí (sellar) |
| Quién firma lo sensible | el aparato que la respalda, a demanda | ella misma, con su certificado |
| Sin conexión | no firma (sí lee lo que ya tiene en el store) | firma |
| Cerrar | inmediato, desde el que respalda | revocar y volver a sellar |
| Necesita la bóveda abierta | **no** | sí |
| Ya existe | no | sí — todo el §1 |
| Precedente en el ecosistema | `dotrino-passmanager`: la extensión pide **de a una** y nunca tiene la bóveda | `pair` |

**La regla que evita tener dos puertas descontroladas:** por defecto se entra como
**sesión**. Convertirse en aparato es un acto aparte, explícito, que pide la bóveda
abierta y la aprobación de siempre. **Ninguna aplicación decide eso sola**, y
tampoco se ofrece «recuérdame en este equipo» como forma encubierta de enrolar.

## 3. La pieza común: la prueba con destinatario

Es la **fase 0** y sirve a las tres direcciones. Vive en `@dotrino/identity` y su
formato ya está fijado en
[`dotrino-sso/docs/DISENO.md` §4](../../dotrino-sso/docs/DISENO.md) — aquí **no se
duplica**:

```ts
requestAssertion({ audience, nonce, scopes }): Promise<Assertion>
verifyAssertion(assertion, { audience, nonce }): Promise<VerifiedIdentity>
```

Lo que este documento añade, porque es propio de las sesiones:

- El `sub` de la prueba es **el perfil**, no la sesión. Una sesión no es otra
  identidad: es la misma persona entrando desde otro sitio.
- La cadena termina en el certificado **del aparato que respalda**, que sí está en
  el acta. Se añade `sid` (la sesión) para que el usuario pueda ver y cortar.
- **Sin modo permisivo al verificar.** Un verificador laxo es un verificador roto.

## 4. El papel de sesión

Una sesión tiene una llave propia `S`, generada en el navegador y **no
extraíble**, que por sí sola no vale nada: nadie la reconoce sin su papel.

```jsonc
{
  "op":     "session",
  "sid":    "<id de la sesión>",
  "s":      "<pubkey de la sesión>",
  "by":     "<pubkey del aparato que respalda>",   // miembro del acta, con su cert
  "origin": "https://chat.dotrino.com",             // dónde vale
  "scopes": ["id:whoami", "vault:store"],
  "iat":    1767000000,
  "exp":    1767028800,                             // horas, no meses
  "sig":    "<firma del aparato que respalda>"
}
```

Se verifica en cadena: `S ← aparato ← acta`. Quien recibe comprueba el papel, y
después comprueba **el certificado del aparato contra el acta de hoy**, igual que
con cualquier otro miembro.

**Esto crea una segunda autoridad, y por eso va acotada por escrito:**

- **Nunca amplía.** Un papel no puede conceder lo que su firmante no tiene.
- **Lista negra fija.** Una sesión jamás lleva `secrets`, `admin`, `approve`,
  `sealer`, `passwords`, `unattended` ni `replica`. Se comprueba al emitir **y** al
  verificar.
- **Vence por reloj.** Es la excepción deliberada a *los certificados ya no caducan
  por reloj* ([`CLAUDE.md`](../../CLAUDE.md)): un certificado describe pertenencia,
  que dura; una sesión **es** temporal, y su vencimiento es la mitad del producto.
- **No se re-delega.** Una sesión no abre otra sesión. La lista de operaciones es
  cerrada, como en la subacta.
- **Muere con su aparato.** Si revocan al que respalda, su certificado deja de valer
  contra el acta y todos sus papeles caen con él. Sale gratis del modelo, y hay que
  probarlo explícitamente.

## 5. Cómo se ve

```
  navegador nuevo                        teléfono (miembro con `approve`)
  ───────────────                        ────────────────────────────────
  «Entrar» → genera S
  muestra QR + código de 6  ────escanea──►  ve: qué aparato, qué aplicación,
  { v, sid, s, proxy, code }                qué permisos y cuánto dura
                                            [Permitir]  [No]
        ◄──── papel de sesión (sellado) ───
  entra                                     lo apunta en «sesiones abiertas»
```

Cuatro cosas que no son detalles:

- **El QR va al revés que en `pair`.** Hoy lo muestra la bóveda y lo escanea el
  aparato nuevo; aquí lo muestra **quien quiere entrar**, porque quien entra puede
  no tener cámara y el teléfono siempre la tiene. Se usa **`@dotrino/qr`**
  (`<dotrino-qr>` / `<dotrino-qr-scan>`), no otra copia.
- **El código de 6 es para cuando no hay cámara**, y se compara igual que el SAS del
  emparejamiento: lo que mata el reenvío es que el atacante no puede enseñar el
  código correcto en la pantalla física de la víctima.
- **Va sellado.** Es un mensaje dirigido: `sendSealed` + `requireSealed`
  (`CONVENCIONES-APPS.md` §4.1). El proxio no cifra.
- **El transporte prefiere el camino más directo** y eso ya lo da el pilar: si el
  teléfono está en la misma red, no hay vuelta a internet.

**El PC con la bóveda abierta respalda igual que el teléfono.** Es el mismo
mecanismo: cualquier miembro con `approve` puede atender la petición. Y como manda
la regla del aparato, **nada de esto necesita un servidor de Dotrino encendido**.

## 6. Qué firma la sesión, y qué no

| Acción | Quién la hace |
|---|---|
| Identificarse ante el proxio, geo, reputación | **la sesión**, con su papel |
| Leer y escribir en el store del perfil | **la sesión**, si su papel lo dice |
| Firmar por la persona (una atestación, un eco, una prueba para un tercero) | **el aparato que respalda**, a demanda |
| Leer un secreto, administrar, aprobar, sellar | **nadie** desde una sesión |

La alternativa —que la sesión no firme absolutamente nada por su cuenta— se estudió
y no sale: cada mensaje del transporte tendría que ir a preguntarle al teléfono.
Queda como decisión revisable (§9).

## 7. Orden de trabajo

| Fase | Qué | Repo |
|---|---|---|
| **F0** ✅ | `requestAssertion` / `verifyAssertion` con `aud`, `nonce`, `iat`, `exp`. Sin modo permisivo. **Hecha el 2026-09-05** en `@dotrino/identity` 0.84.0 (`vault/assertion.js`), con `verifySignedFor` para lo que se publica. **Cableada en geo** (cliente 0.9.0) **y en reputación** (cliente 0.11.0): un pin o una atestación sin destinatario, o firmados para otro servicio, se rechazan. **Falta solo el proxio**, que es el caso interactivo, con reto. | `dotrino-identity` (+ `dotrino-vault`) |
| **F1** ✅ | **Sesiones**: papel, flujo de las dos puntas, QR inverso, lista y cierre. **Hecha el 2026-09-05** en `@dotrino/identity` 0.85.0 (`vault/session.js` + `vault/sessionFlow.js`, 19 pruebas) y cableada en **`profile.dotrino.com/sessions`**, comprobada de punta a punta contra el proxio de producción. | `@dotrino/identity`, `dotrino-profile-app` |
| **F2** ✅ | Permiso por origen y alcances, **diseñado para el caso ajeno desde el principio**. **Hecha el 2026-09-06** en `@dotrino/identity` 0.86.1: saber quién eres no cuesta permiso, cualquier dato tuyo sí; el panel lo pinta la BÓVEDA (otro origen: la app no puede pulsarlo ni leerlo) y lo concedido se ve y se retira en `profile.dotrino.com/sessions`. | `@dotrino/identity`, `dotrino-profile-app` |
| **F3** ✅ | Puente OpenID Connect + `@dotrino/sso-client`. **Hecho el 2026-09-06** y en vivo en `sso.dotrino.com`: Authorization Code con PKCE S256, `id_token` ES256, sin base de datos de usuarios. Comprobado de punta a punta en producción. | `dotrino-sso` |
| **F4** ✅ | «Dónde se usó mi identidad»: sesiones abiertas **y** aplicaciones ajenas en **una sola lista**, con su último uso y quién pedía de verdad (`onBehalfOf`, subordinado al origen). **Hecha el 2026-09-06.** | `@dotrino/identity` 0.87, `dotrino-profile-app` |
| **F5** | Federación entrante: Active Directory respalda al usuario. **Lo único que queda del plan.** | `dotrino-ad-integration` |
| **F6** ✅ | Landing pública y catálogo. En la copy, «SSO» es argot: *un solo inicio de sesión para todo*. **Hecha el 2026-09-06**: la sirve el propio puente (un `git pull` despliega todo) y el aviso de lo que ese servicio ve está en la propia página, con sus dos salidas al lado. | `dotrino-sso/web`, `dotrino-home` |

F0 va primero porque sin destinatario no hay nada de lo demás, y porque cierra hoy
el cruce entre proxio, geo y reputación. **Toca el pilar que usan todas las apps:**
cambio limpio en los dos lados y se publica, sin capa de compatibilidad, y anunciando
versión con `@dotrino/compat` (§14) — una incompatibilidad de versiones se manifiesta
como silencio.

F4 lleva las dos cosas a la misma pantalla a propósito. Dos listas —«mis sesiones» y
«mis aplicaciones»— se desincronizan y obligan al usuario a saber la diferencia.

### Lo que F1 dejó fuera, y hay que decirlo

- **El papel no se renueva**: cuando vence, se vuelve a entrar. Renovarlo mientras el que
  respalda siga vivo es cómodo, pero alarga la vida de una llave que está en un aparato que
  no es tuyo, así que se decide aparte.
- **Las sesiones dadas se guardan en `localStorage`**, no en el store. En el aparato que
  entra no hay otra cosa —todavía no tiene identidad, que es justo lo que viene a
  conseguir—, pero en el que respalda sí la hay y ahí corresponde el store.
- **Ninguna app consume todavía el papel**: `verifySessionSigned` existe y está probado,
  pero quien lo va a pedir es F2 (permiso por origen) y los servicios. Hasta entonces, una
  sesión sirve para entrar y verse, no para usar el ecosistema entero.

## 8. Lo que NO se hace

- **Contraseña de cuenta Dotrino, ni recuperación por correo.** No hay nadie que la
  pueda dar. Si se pierde la maestra del perfil, se pierde la cuenta, y eso se dice
  en voz alta.
- **«Entrar con Google» como forma de tener cuenta.** Un proveedor externo puede
  **respaldar** una llave (`op:'verify'` de `@dotrino/verifier`); no puede
  custodiarla ni devolverla. Confundir las dos cosas convierte al ecosistema en lo
  contrario de lo que es.
- **Sesiones que sellen, administren, aprueben o lean secretos.** Ni con permiso.
- **Cierre de sesión global de OIDC**: exigiría que el puente guarde dónde entraste,
  que es justo lo que decidimos no guardar. Se explica en vez de soportarlo a medias.
- **Un login que dependa de un daemon o de un servidor encendido.** Regla del
  aparato: lo dedicado añade alcance, nunca es requisito.
- **Repliegues.** Si falta el papel, el acta o el destinatario para decidir, se para
  y se dice con un error que se pueda buscar. `if (papel && !vale)` significa «sin
  papel, pasa».

## 9. Decisiones pendientes

| Tema | Pregunta |
|---|---|
| ~~**Alcance de la sesión**~~ | **Decidido (2026-09-05): firma sola lo de bajo riesgo.** Todo a demanda obliga a molestar al aparato que respalda en cada mensaje del transporte. La lista quedó en `id:whoami` y `vault:store`; firmar por la persona no está, y eso es lo que se pide al aparato. |
| **Duración** | Por ahora 8 h por defecto y tope de 24, sin renovación: cuando vence se vuelve a entrar. Falta decidir si se renueva sola mientras el que respalda esté vivo. |
| **Identificador por pares** | Heredada del SSO: ¿el mismo `sub` en todas las aplicaciones, o derivado por aplicación para que nadie pueda cruzarlas? |
| **Correo respaldado** | ¿`profile:email` se bloquea hasta que `@dotrino/verifier` esté cableado, o se entrega marcado como *declarado*? |
| **Sesión sin teléfono a mano** | Si el único miembro con `approve` está apagado, ¿se puede entrar de otro modo, o se acepta que no? |
| **Enseñar la sesión al otro lado** | Un servicio que ve una sesión, ¿debe distinguirla de un aparato en su registro? |

## 10. Referencias

- [`pairing-protocol.md`](./pairing-protocol.md) — el emparejamiento endurecido: por
  qué el token dejó de ser autoridad suficiente, y de dónde sale el SAS.
- [`acta-de-perfil.md`](./acta-de-perfil.md) — quién puede qué en un perfil.
- [`../src/subacta.js`](../src/subacta.js) — por qué lo que solo quita puede vivir
  sin la selladora, y lo que da no.
- [`dotrino-sso/docs/DISENO.md`](../../dotrino-sso/docs/DISENO.md) — el formato de la
  prueba firmada, los alcances y el puente OpenID Connect.
- [`dotrino-ad-integration/docs/DISENO.md`](../../dotrino-ad-integration/docs/DISENO.md)
  — la dirección contraria: la empresa respalda al usuario.
- [`dotrino-passmanager/docs/DISENO.md`](../../dotrino-passmanager/docs/DISENO.md) —
  el precedente de «pide de a una y nunca tengas la bóveda entera».
