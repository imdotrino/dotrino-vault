/**
 * pair.js — vault.dotrino.com/pair
 *
 * Emparejador SELF independiente del ecosistema: este navegador actúa como vault
 * (levanta el daemon con startDeviceVault) y enlaza dispositivos/agentes (genera el
 * código de emparejamiento, aprueba con SAS, lista los enlazados).
 *
 * Las apps llegan con ?back=<url>; tras enlazar, un botón vuelve a esa URL.
 * Centraliza lo que antes duplicaban selfTerminalScreen / selfIaScreen.
 */
import '@dotrino/topbar'
import './pair.css'
import { Identity } from '@dotrino/identity'
import { startDeviceVault } from '@dotrino/vault'
import { pubkeyId } from '@dotrino/identity/capabilities'
import { qrSvg } from './qr.js'

const I18N = {
  es: {
    h: 'Enlazar una máquina a tu vault',
    intro: 'Este navegador es tu vault. Genera un código y pégalo en el agente o app para enlazarlo.',
    pair_new: 'Generar código de emparejamiento',
    pair_step1: 'Pega este código en la máquina del agente:',
    pair_step2: 'El agente pedirá aprobación con un código que TIPEAS aquí.',
    pair_wait: 'Esperando a que pida acceso…',
    copy: 'Copiar código', copied: 'Copiado', cancel: 'Cancelar',
    pending: (d) => `La máquina ${d} pide acceso. Tipea el código que muestra:`,
    code_ph: 'código', approve: 'Aprobar', reject: 'Rechazar',
    machines_title: 'Máquinas enlazadas', machines_none: 'Aún no hay máquinas enlazadas.',
    back_app: (h) => `Volver a ${h}`,
    need_identity: 'Necesitas una identidad primero. Créala en',
    proxy_err: 'No se pudo conectar al proxy para actuar como vault.',
    retry: 'Reintentar',
    active: (d) => `Vault activo · ${d}`
  },
  en: {
    h: 'Link a machine to your vault',
    intro: 'This browser is your vault. Generate a code and paste it in the agent or app to link it.',
    pair_new: 'Generate pairing code',
    pair_step1: 'Paste this code in the agent machine:',
    pair_step2: 'The agent will ask for approval with a code you TYPE here.',
    pair_wait: 'Waiting for it to request access…',
    copy: 'Copy code', copied: 'Copied', cancel: 'Cancel',
    pending: (d) => `Machine ${d} requests access. Type the code it shows:`,
    code_ph: 'code', approve: 'Approve', reject: 'Reject',
    machines_title: 'Linked machines', machines_none: 'No machines linked yet.',
    back_app: (h) => `Back to ${h}`,
    need_identity: 'You need an identity first. Create one at',
    proxy_err: 'Could not connect to the proxy to act as vault.',
    retry: 'Retry',
    active: (d) => `Vault active · ${d}`
  }
}

let lang = document.documentElement.lang === 'en' ? 'en' : 'es'
const t = (k, ...a) => String(typeof I18N[lang][k] === 'function' ? I18N[lang][k](...a) : (I18N[lang][k] ?? k))
const el = (h) => { const tp = document.createElement('template'); tp.innerHTML = h.trim(); return tp.content.firstElementChild }
const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]))

// ?back= URL de la app que nos llamó (solo http/https, para evitar open-redirect).
function backUrl () {
  const b = new URLSearchParams(location.search).get('back')
  if (!b) return null
  try { const u = new URL(b); if (u.protocol === 'http:' || u.protocol === 'https:') return u.origin + u.pathname } catch {}
  return null
}
function backHost () { try { return backUrl() ? new URL(backUrl()).hostname : null } catch { return null } }
function goBack () { const u = backUrl(); location.href = u || 'https://dotrino.com/' }

const app = document.getElementById('app')

async function wireTopbar () {
  const tb = document.getElementById('topbar')
  tb.setAttribute('lang', lang)
  tb.addEventListener('dotrino-lang', (e) => {
    lang = e.detail?.lang === 'en' ? 'en' : 'es'
    document.documentElement.lang = lang
    try { localStorage.setItem('dotrino-lang', lang) } catch {}
    render()
  })
}

async function render () {
  const bh = backHost()
  const backBtn = bh ? `<button class="back-app" id="backApp" data-testid="pair-back">${t('back_app', esc(bh))}</button>` : ''
  app.replaceChildren(el(`<section class="card"><span class="status">${t('proxy_err')}</span></section>`))

  let id
  try { id = await Identity.connect() } catch {}
  if (!id?.me?.publickey) {
    app.replaceChildren(el(`<section class="card"><b>${t('need_identity')}</b>
      <p><a class="primary" href="https://profile.dotrino.com" target="_blank" rel="noopener">profile.dotrino.com</a></p>
      <p>${backBtn}</p></section>`))
    document.getElementById('backApp')?.addEventListener('click', goBack)
    return
  }

  let sm
  try { sm = await startDeviceVault(id) }
  catch (_) {
    app.replaceChildren(el(`<section class="card"><p class="status">${t('proxy_err')}</p>
      <p><button id="retry" class="primary">${t('retry')}</button> ${backBtn}</p></section>`))
    document.getElementById('retry')?.addEventListener('click', render)
    document.getElementById('backApp')?.addEventListener('click', goBack)
    return
  }
  const devShort = (await pubkeyId(sm.iss)).slice(0, 8).toUpperCase().replace(/(.{4})(.{4})/, '$1-$2')

  app.replaceChildren(el(`<section class="card">
    <h1>${t('h')}</h1>
    <p class="status">${t('intro')}</p>
    <span class="hint">${t('active', esc(devShort))}</span>
    <div id="pair" class="block"></div>
    <div id="machines" class="block"><span class="status">${t('machines_none')}</span></div>
    ${backBtn ? `<p>${backBtn}</p>` : ''}
  </section>`))
  document.getElementById('backApp')?.addEventListener('click', goBack)

  const pairBox = document.getElementById('pair')
  const machinesBox = document.getElementById('machines')

  // --- Emparejamiento: genera código + QR, aprueba con SAS ---
  function renderPairIdle () {
    pairBox.innerHTML = `<div class="setup"><button id="startPair" class="primary" data-testid="start-pair">${t('pair_new')}</button></div>`
    document.getElementById('startPair').addEventListener('click', startPairing)
  }
  function startPairing () {
    const { qr } = sm.startPairing()
    const payload = JSON.stringify(qr)
    pairBox.innerHTML = `<div class="setup">
      <p class="status">${t('pair_step1')}</p>
      <div class="qr-wrap" title="QR">${qrSvg(payload)}</div>
      <div class="qr-code"><pre><code>${esc(payload)}</code></pre></div>
      <button id="copyQr" class="link">${t('copy')}</button>
      <span class="status" id="copyMsg"></span>
      <p class="status">${t('pair_step2')}</p>
      <p class="status">⏳ ${t('pair_wait')}</p>
      <button id="cancelPair" class="link">${t('cancel')}</button>
    </div>`
    document.getElementById('copyQr').addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(payload); document.getElementById('copyMsg').textContent = t('copied') } catch {}
    })
    document.getElementById('cancelPair').addEventListener('click', renderPairIdle)
  }
  // NO mostramos el código SAS: el humano lo LEE de la máquina y lo TIPEA aquí.
  function renderPending (list) {
    if (!list || !list.length) { if (pairBox.querySelector('[data-pending]')) renderPairIdle(); return }
    const rows = list.map((x) => `
      <div class="pending" data-pending data-device="${esc(x.deviceId)}">
        <p class="status">${t('pending', esc(x.deviceId))}</p>
        <div class="pair-actions">
          <input class="code-input" data-code="${esc(x.deviceId)}" type="text" inputmode="numeric"
                 autocomplete="off" maxlength="8" placeholder="${esc(t('code_ph'))}"
                 aria-label="${esc(t('code_ph'))}" data-testid="pair-code" />
          <button class="primary" data-approve="${esc(x.deviceId)}" data-testid="pair-approve">${t('approve')}</button>
          <button class="link" data-reject="${esc(x.deviceId)}">${t('reject')}</button>
        </div>
      </div>`).join('')
    pairBox.innerHTML = `<div class="setup">${rows}</div>`
    const approveWith = async (b) => {
      const dev = b.dataset.approve
      const input = pairBox.querySelector(`input[data-code="${CSS.escape(dev)}"]`)
      const code = (input?.value || '').trim()
      if (!code) { input?.focus(); return }
      b.disabled = true
      try { await sm.approve(dev, code); refreshMachines() } catch (e) { b.disabled = false }
    }
    pairBox.querySelectorAll('[data-approve]').forEach((b) => {
      b.addEventListener('click', () => approveWith(b))
      const input = pairBox.querySelector(`input[data-code="${CSS.escape(b.dataset.approve)}"]`)
      input?.addEventListener('keydown', (e) => { if (e.key === 'Enter') approveWith(b) })
    })
    pairBox.querySelectorAll('[data-reject]').forEach((b) => b.addEventListener('click', () => sm.reject(b.dataset.reject)))
  }
  sm.onPendingChange(() => renderPending(sm.listPending()))
  renderPairIdle()

  // --- Lista de máquinas enlazadas ---
  async function refreshMachines () {
    try {
      const list = await sm.listMachines()
      if (!list.length) {
        machinesBox.innerHTML = `<span class="status">${t('machines_none')}</span>`
        // Sin máquinas y sin pendientes → enseña el QR de una (fricción cero).
        if (!sm.listPending().length && !pairBox.querySelector('.qr-wrap')) startPairing()
        return
      }
      machinesBox.innerHTML = `<b>${t('machines_title')}</b><div class="machine-list"></div>`
      const holder = machinesBox.querySelector('.machine-list')
      for (const d of list) {
        const name = d.label ? `${d.label} · ${d.deviceId}` : d.deviceId
        holder.appendChild(el(`<div class="machine-row" data-sub="${esc(d.sub)}"><span class="machine-name">🖥 ${esc(name)}</span></div>`))
      }
    } catch { machinesBox.innerHTML = `<span class="status">${t('machines_none')}</span>` }
  }
  refreshMachines()
  const _origApprove = sm.approve.bind(sm)
  sm.approve = async (...a) => { const r = await _origApprove(...a); refreshMachines(); return r }
}

(async () => {
  const saved = (() => { try { return localStorage.getItem('dotrino-lang') } catch { return null } })()
  if (saved === 'en' || saved === 'es') { lang = saved; document.documentElement.lang = lang }
  await wireTopbar()
  await render()
})()
