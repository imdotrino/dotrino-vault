<script setup>
import { ref, computed, onMounted } from 'vue'

const GITHUB = 'https://github.com/imdotrino/dotrino-vault'
const RELEASES = GITHUB + '/releases/latest'
const DISCORD = 'https://discord.gg/D648uq7cth'

/* ---------------- i18n (es/en · tuteo, sin voseo) ---------------- */
const I18N = {
  es: {
    nav_how: 'Cómo funciona', nav_download: 'Descargar',
    hero_kicker: 'Certificador personal · self-hosted',
    hero_title: 'Sé tu propia autoridad',
    hero_sub: 'Tu identidad y tus llaves viven en tu máquina —no en Google, Apple ni una autoridad central. Dotrino Vault custodia tu llave maestra y te deja certificar tus dispositivos y documentos tú mismo. Tú firmas, tú decides.',
    hero_download: 'Descargar para Linux', hero_source: 'Ver el código',
    hero_note: 'v1 para Linux (x64). macOS y Windows, pronto.',
    why_title: '¿Por qué?',
    why_body: 'Hoy unas pocas plataformas deciden quién eres en internet: el «Inicia sesión con Google/Apple», las autoridades de certificación, los verificadores de identidad, el tilde azul. Dotrino Vault te devuelve ese poder. Es un servicio que corre en tu propia máquina, custodia tu llave maestra y te convierte en tu propia autoridad: certificas por ti mismo, sin pedirle permiso a nadie.',
    how_title: 'Cómo funciona',
    how_1_t: 'Instalas y corre solo',
    how_1_b: 'Un servicio headless que arranca con tu equipo. En el primer arranque genera tu identidad. Tu llave maestra nunca sale de tu máquina.',
    how_2_t: 'Enrolas tus dispositivos',
    how_2_b: 'Tu teléfono o tu laptop escanean un QR y reciben un certificado firmado por tu llave —sin copiar la llave. Cada dispositivo tiene la suya.',
    how_3_t: 'Firmas y revocas',
    how_3_b: 'Tus dispositivos te piden firmar o leer; el vault responde por un canal cifrado. ¿Perdiste un equipo? Lo revocas y listo. La maestra sigue intacta.',
    feat_title: 'Lo que te da',
    feats: [
      ['Tu llave nunca sale', 'La maestra se queda en tu máquina. Los dispositivos actúan con un certificado acotado, revocable y con vencimiento.'],
      ['Sin porteros', 'Sin CAs, sin login de terceros, sin KYC. Tú eres la autoridad de tu propia identidad.'],
      ['Multi-dispositivo', 'La misma identidad en tu PC, tu laptop y tu teléfono, hablando entre ellos de forma segura.'],
      ['Web-of-trust', 'Tus certificados los puede verificar cualquiera del ecosistema, sin preguntarte a ti.'],
      ['Headless', 'Corre como servicio del sistema, sin navegador. La interfaz es opcional.'],
      ['Open source', 'Código abierto (MIT) y autohospedado. Sin anuncios, sin cookies, sin rastreo.'],
    ],
    dl_title: 'Descarga',
    dl_lead: 'Un solo archivo, con todo dentro: no necesitas instalar Node ni dependencias. Se instala como servicio y arranca solo.',
    dl_btn: 'Descargar para Linux (x64)',
    dl_install_t: 'Instalar',
    dl_pair_t: 'Emparejar un dispositivo',
    dl_warn: 'El binario no está firmado (es self-hosted y de código abierto): tu sistema puede mostrar una advertencia. En Linux basta con darle permiso de ejecución; el instalador lo hace.',
    dl_other: 'macOS y Windows están en camino (v2). Mientras tanto, puedes compilarlo tú desde el código.',
    foot_tag: 'Tu información, en tu servidor, bajo tus reglas.',
    foot_eco: 'Parte del ecosistema Dotrino', foot_src: 'Código', foot_discord: 'Discord',
  },
  en: {
    nav_how: 'How it works', nav_download: 'Download',
    hero_kicker: 'Personal certifier · self-hosted',
    hero_title: 'Be your own authority',
    hero_sub: 'Your identity and your keys live on your machine — not on Google, Apple or a central authority. Dotrino Vault guards your master key and lets you certify your own devices and documents. You sign, you decide.',
    hero_download: 'Download for Linux', hero_source: 'View the code',
    hero_note: 'v1 for Linux (x64). macOS and Windows, soon.',
    why_title: 'Why?',
    why_body: 'Today a handful of platforms decide who you are online: "Sign in with Google/Apple", certificate authorities, identity verifiers, the blue check. Dotrino Vault gives that power back to you. It is a service that runs on your own machine, guards your master key and makes you your own authority: you certify yourself, asking no one for permission.',
    how_title: 'How it works',
    how_1_t: 'Install it and it just runs',
    how_1_b: 'A headless service that starts with your machine. On first run it generates your identity. Your master key never leaves your machine.',
    how_2_t: 'Enroll your devices',
    how_2_b: 'Your phone or laptop scans a QR and gets a certificate signed by your key — without copying the key. Each device holds its own.',
    how_3_t: 'Sign and revoke',
    how_3_b: 'Your devices ask to sign or read; the vault answers over an encrypted channel. Lost a device? Revoke it and done. The master key stays intact.',
    feat_title: 'What you get',
    feats: [
      ['Your key never leaves', 'The master key stays on your machine. Devices act with a scoped, revocable, expiring certificate.'],
      ['No gatekeepers', 'No CAs, no third-party login, no KYC. You are the authority of your own identity.'],
      ['Multi-device', 'The same identity on your PC, laptop and phone, talking to each other securely.'],
      ['Web of trust', 'Anyone in the ecosystem can verify your certificates without asking you.'],
      ['Headless', 'Runs as a system service, no browser needed. The UI is optional.'],
      ['Open source', 'Open source (MIT) and self-hosted. No ads, no cookies, no tracking.'],
    ],
    dl_title: 'Download',
    dl_lead: 'A single file with everything inside: no Node, no dependencies to install. It installs as a service and starts on its own.',
    dl_btn: 'Download for Linux (x64)',
    dl_install_t: 'Install',
    dl_pair_t: 'Pair a device',
    dl_warn: 'The binary is unsigned (it is self-hosted and open source): your system may show a warning. On Linux it only needs execute permission; the installer handles it.',
    dl_other: 'macOS and Windows are on the way (v2). In the meantime you can build it yourself from source.',
    foot_tag: 'Your data, on your server, under your rules.',
    foot_eco: 'Part of the Dotrino ecosystem', foot_src: 'Source', foot_discord: 'Discord',
  },
}
const LANG_KEY = 'vault.lang'
const lang = ref((localStorage.getItem(LANG_KEY) || (navigator.language || 'es').slice(0, 2)) === 'en' ? 'en' : 'es')
const t = computed(() => I18N[lang.value])
const setLang = (l) => { lang.value = l; localStorage.setItem(LANG_KEY, l); document.documentElement.lang = l }

const installCmd = 'tar xzf dotrino-vault-*-linux-x64.tar.gz\ncd dotrino-vault-*-linux-x64\nsh install.sh'
const pairCmd = 'dotrino-vault pair'

const copied = ref('')
function copy (text, key) {
  navigator.clipboard?.writeText(text).then(() => { copied.value = key; setTimeout(() => (copied.value = ''), 1400) })
}

onMounted(() => { document.documentElement.lang = lang.value })
</script>

<template>
  <div class="page">
    <header class="topbar">
      <a class="brand" href="/"><img src="/icon.svg" alt="" width="30" height="30" /><span>Dotrino&nbsp;Vault</span></a>
      <nav class="navlinks">
        <a href="#how">{{ t.nav_how }}</a>
        <a href="#download">{{ t.nav_download }}</a>
      </nav>
      <div class="actions">
        <div class="lang-selector" role="group" aria-label="es / en">
          <button :class="{ on: lang === 'es' }" @click="setLang('es')">ES</button>
          <button :class="{ on: lang === 'en' }" @click="setLang('en')">EN</button>
        </div>
        <dotrino-install :lang="lang"></dotrino-install>
        <dotrino-support href="https://ko-fi.com/dotrino" repo="imdotrino/dotrino-vault" :discord="DISCORD" :lang="lang"></dotrino-support>
      </div>
    </header>

    <main>
      <!-- HERO -->
      <section class="hero">
        <p class="kicker">{{ t.hero_kicker }}</p>
        <h1>{{ t.hero_title }}</h1>
        <p class="lead">{{ t.hero_sub }}</p>
        <div class="cta">
          <a class="btn btn-primary" :href="RELEASES" data-testid="hero-download">↓ {{ t.hero_download }}</a>
          <a class="btn btn-ghost" :href="GITHUB">{{ t.hero_source }}</a>
        </div>
        <p class="note">{{ t.hero_note }}</p>
        <div class="shield" aria-hidden="true"><img src="/icon.svg" alt="" width="160" height="160" /></div>
      </section>

      <!-- WHY -->
      <section class="why">
        <h2>{{ t.why_title }}</h2>
        <p>{{ t.why_body }}</p>
      </section>

      <!-- HOW -->
      <section id="how" class="how">
        <h2>{{ t.how_title }}</h2>
        <ol class="steps">
          <li><span class="num">1</span><div><h3>{{ t.how_1_t }}</h3><p>{{ t.how_1_b }}</p></div></li>
          <li><span class="num">2</span><div><h3>{{ t.how_2_t }}</h3><p>{{ t.how_2_b }}</p></div></li>
          <li><span class="num">3</span><div><h3>{{ t.how_3_t }}</h3><p>{{ t.how_3_b }}</p></div></li>
        </ol>
      </section>

      <!-- FEATURES -->
      <section class="features">
        <h2>{{ t.feat_title }}</h2>
        <div class="grid">
          <div class="feat" v-for="(f, i) in t.feats" :key="i">
            <h3>{{ f[0] }}</h3><p>{{ f[1] }}</p>
          </div>
        </div>
      </section>

      <!-- DOWNLOAD -->
      <section id="download" class="download">
        <h2>{{ t.dl_title }}</h2>
        <p class="lead">{{ t.dl_lead }}</p>
        <a class="btn btn-primary btn-lg" :href="RELEASES" data-testid="download">↓ {{ t.dl_btn }}</a>

        <div class="codeblock">
          <div class="code-head"><span>{{ t.dl_install_t }}</span>
            <button class="copy" @click="copy(installCmd, 'install')">{{ copied === 'install' ? '✓' : '⧉' }}</button>
          </div>
          <pre><code>{{ installCmd }}</code></pre>
        </div>
        <div class="codeblock">
          <div class="code-head"><span>{{ t.dl_pair_t }}</span>
            <button class="copy" @click="copy(pairCmd, 'pair')">{{ copied === 'pair' ? '✓' : '⧉' }}</button>
          </div>
          <pre><code>{{ pairCmd }}</code></pre>
        </div>

        <p class="warn">{{ t.dl_warn }}</p>
        <p class="other">{{ t.dl_other }}</p>
      </section>
    </main>

    <footer class="foot">
      <p class="foot-tag">{{ t.foot_tag }}</p>
      <nav class="foot-links">
        <a :href="GITHUB">{{ t.foot_src }}</a>
        <a :href="DISCORD">{{ t.foot_discord }}</a>
        <a href="https://dotrino.com">{{ t.foot_eco }}</a>
      </nav>
      <p class="foot-lic">MIT · Dotrino</p>
    </footer>
  </div>
</template>
