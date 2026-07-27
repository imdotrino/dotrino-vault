<script setup>
import { ref, computed, onMounted } from 'vue'
import Consola from './Console.vue'

const GITHUB = 'https://github.com/imdotrino/dotrino-vault'
const RELEASES = GITHUB + '/releases/latest'
const DISCORD = 'https://discord.gg/D648uq7cth'

/* ---------------- i18n (es/en · tuteo, sin voseo · lenguaje llano) ---------------- */
const I18N = {
  es: {
    nav_how: 'Cómo funciona', nav_download: 'Descargar', nav_devices: 'Mis dispositivos', nav_home: 'Inicio',
    hero_kicker: 'Tu bóveda personal · en tu propia máquina',
    hero_title: 'Toda tu información, en un solo lugar seguro',
    hero_sub: 'Tus archivos, tus contactos, tus contraseñas y lo que guardan tus apps, todo junto en una bóveda que vive en tu propia computadora. No en la nube de una empresa: en tu máquina, bajo tu control. Sin anuncios, sin rastreo, sin que nadie venda tus datos.',
    hero_download: 'Descargar gratis', hero_source: 'Ver el código',
    hero_note: 'Por ahora para Linux. macOS y Windows, pronto.',
    why_title: '¿Para qué sirve?',
    why_body: 'Hoy tu información está repartida y, casi siempre, en servidores de grandes empresas que la guardan, la miran y la usan para ganar dinero: unas cosas en Google, otras en tu teléfono, otras en cada app. Dotrino Vault las junta en un solo lugar que es tuyo de verdad —tu computadora— y tus demás dispositivos acceden a ella de forma segura, estés donde estés. Tu información deja de estar prestada y vuelve a ser tuya.',
    how_title: 'Cómo funciona',
    how_1_t: 'Lo instalas',
    how_1_b: 'Descargas un programa que se queda funcionando en tu computadora y se encarga de guardar tus cosas. Queda listo en un minuto, sin configurar nada.',
    how_2_t: 'Conectas tus dispositivos',
    how_2_b: 'Escaneas un código con tu teléfono o tu laptop y quedan conectados a tu bóveda. Cada uno con su propio permiso, que puedes quitar cuando quieras.',
    how_3_t: 'Todo seguro, en un lugar',
    how_3_b: 'Tu información vive en tu máquina y solo la ven los dispositivos que tú conectaste. ¿Perdiste el teléfono? Lo desconectas con un clic y tus datos siguen a salvo.',
    feat_title: 'Lo que te da',
    feats: [
      ['Todo junto', 'Archivos, contactos, notas y lo que guardan tus apps: una sola bóveda, en vez de tus cosas regadas por mil sitios.'],
      ['Es tuya', 'Vive en tu propia computadora, no en los servidores de una empresa. Tú eres el único dueño.'],
      ['Privada de verdad', 'Sin anuncios, sin cookies, sin rastreo. Nadie mira ni vende tu información.'],
      ['En todos tus dispositivos', 'Tu teléfono, tu laptop y tu PC, conectados a la misma bóveda de forma segura.'],
      ['Tú decides quién entra', 'Conectas y desconectas dispositivos cuando quieras. El control es solo tuyo.'],
      ['Gratis y abierta', 'No cuesta nada y no pide cuenta. Su código es abierto, para que cualquiera lo revise.'],
    ],
    dl_title: 'Descarga',
    dl_lead: 'Gratis, un solo archivo con todo dentro. Lo descargas, lo instalas y tu bóveda queda funcionando sola.',
    dl_deb_t: 'Ubuntu o Debian',
    dl_deb_btn: 'Descargar el instalador (.deb)',
    dl_deb_note: 'Descarga el archivo .deb, haz doble clic y se instala solo (o en la terminal: sudo apt install ./dotrino-vault_*.deb). Queda funcionando al instante.',
    dl_tar_t: 'Otro Linux',
    dl_tar_btn: 'Descargar (.tar.gz)',
    dl_install_t: 'Instalar',
    dl_pair_t: 'Conectar un dispositivo',
    dl_warn: 'Como es un programa gratuito y de código abierto (no le pagamos a nadie por "firmarlo"), tu sistema puede mostrarte un aviso al instalarlo. Es normal y seguro.',
    dl_other: 'Las versiones para macOS y Windows están en camino. Por ahora, Linux.',
    nav_use: 'Cómo se usa',
    use_title: 'Cómo se usa, una vez instalada',
    use_lead: 'Casi todo el tiempo no tienes que hacer nada: la bóveda arranca sola con la computadora y trabaja de fondo. Esto es lo poco que sí harás alguna vez.',
    use_cards: [
      ['Conectar un teléfono o una laptop',
       'En tu computadora pides un código; en el aparato lo escaneas o lo pegas. El aparato te muestra seis dígitos y tú los escribes en la computadora. Ese ida y vuelta es lo que evita que alguien se cuele: aprobar exige tener el aparato en la mano.'],
      ['Ver quién está conectado',
       'Tu página de dispositivos lista cada aparato, qué puede hacer cada uno y cuál manda. Desde ahí quitas permisos o sacas a uno del todo.'],
      ['Si pierdes un aparato',
       'Lo desconectas y deja de servir: la bóveda no vuelve a firmar por él y, la próxima vez que se encienda, se borra lo que tenía de tu cuenta.'],
      ['Tener varias cuentas',
       'Puedes guardar más de una cuenta en la misma computadora (la personal y la del trabajo, por ejemplo). Funcionan a la vez y no se ven entre ellas.'],
      ['Ponerle una contraseña',
       'Opcional. Protege que otro que se siente en tu computadora te cambie la cuenta. No protege el disco, y tus aparatos siguen funcionando aunque esté puesta.'],
    ],
    use_warn_t: 'Lo más importante que tienes que saber',
    use_warn_b: 'Tu cuenta vive en esta computadora y en ningún otro lado. No hay una copia nuestra ni una forma de recuperarla: si pierdes la máquina sin haber conectado otra bóveda antes, pierdes la cuenta. Es el precio de que sea tuya de verdad, y preferimos decírtelo antes que prometerte un rescate que no existe.',
    use_cmds_t: 'Los comandos, si te manejas con la terminal',
    use_cmds: [
      ['dotrino-vault status', 'ver si está funcionando'],
      ['dotrino-vault pair', 'conectar un aparato (muestra el código)'],
      ['dotrino-vault approve <código>', 'aprobar el aparato con los dígitos que él muestra'],
      ['dotrino-vault members', 'quién está en tu cuenta y qué puede hacer'],
      ['dotrino-vault caps <ID> -firma', 'quitarle un permiso a un aparato'],
      ['dotrino-vault revoke <nonce>', 'sacar un aparato del todo'],
      ['dotrino-vault activity', 'bitácora: qué se firmó y quién entró'],
      ['dotrino-vault profile ls', 'tus cuentas en esta computadora'],
      ['dotrino-vault tui', 'todo lo anterior, en una pantalla'],
    ],
    use_service_t: 'Y el servicio, si algo se atasca',
    use_more: 'Todo esto también está en tu página de dispositivos, sin terminal.',
    foot_tag: 'Tu información, en tu lugar, bajo tus reglas.',
    foot_eco: 'Parte del ecosistema Dotrino', foot_src: 'Código', foot_discord: 'Discord',
  },
  en: {
    nav_how: 'How it works', nav_download: 'Download', nav_devices: 'My devices', nav_home: 'Home',
    hero_kicker: 'Your personal vault · on your own machine',
    hero_title: 'All your information, in one safe place',
    hero_sub: 'Your files, your contacts, your passwords and whatever your apps save, all together in a vault that lives on your own computer. Not on a company’s cloud: on your machine, under your control. No ads, no tracking, nobody selling your data.',
    hero_download: 'Download free', hero_source: 'View the code',
    hero_note: 'For Linux for now. macOS and Windows, soon.',
    why_title: 'What is it for?',
    why_body: 'Today your information is scattered and, almost always, sitting on big companies’ servers that keep it, look at it and use it to make money: some things on Google, others on your phone, others in each app. Dotrino Vault brings it all into one place that is truly yours —your computer— and your other devices reach it securely, wherever you are. Your information stops being borrowed and becomes yours again.',
    how_title: 'How it works',
    how_1_t: 'You install it',
    how_1_b: 'You download a program that keeps running on your computer and takes care of storing your stuff. Ready in a minute, nothing to configure.',
    how_2_t: 'You connect your devices',
    how_2_b: 'You scan a code with your phone or laptop and they get connected to your vault. Each one with its own permission, which you can remove whenever you want.',
    how_3_t: 'Everything safe, in one place',
    how_3_b: 'Your information lives on your machine and only the devices you connected can see it. Lost your phone? Disconnect it with one click and your data stays safe.',
    feat_title: 'What you get',
    feats: [
      ['Everything together', 'Files, contacts, notes and whatever your apps save: one single vault, instead of your stuff spread across a thousand places.'],
      ['It’s yours', 'It lives on your own computer, not on a company’s servers. You are the only owner.'],
      ['Truly private', 'No ads, no cookies, no tracking. Nobody looks at or sells your information.'],
      ['On all your devices', 'Your phone, laptop and PC, connected to the same vault securely.'],
      ['You decide who gets in', 'Connect and disconnect devices whenever you want. The control is only yours.'],
      ['Free and open', 'It costs nothing and asks for no account. Its code is open for anyone to review.'],
    ],
    dl_title: 'Download',
    dl_lead: 'Free, a single file with everything inside. Download it, install it and your vault runs on its own.',
    dl_deb_t: 'Ubuntu or Debian',
    dl_deb_btn: 'Download the installer (.deb)',
    dl_deb_note: 'Download the .deb file, double-click and it installs on its own (or in a terminal: sudo apt install ./dotrino-vault_*.deb). Up and running instantly.',
    dl_tar_t: 'Other Linux',
    dl_tar_btn: 'Download (.tar.gz)',
    dl_install_t: 'Install',
    dl_pair_t: 'Connect a device',
    dl_warn: 'Since it’s a free, open-source program (we don’t pay anyone to "sign" it), your system may show a warning when installing. That’s normal and safe.',
    dl_other: 'macOS and Windows versions are on the way. For now, Linux.',
    nav_use: 'How to use it',
    use_title: 'How to use it, once installed',
    use_lead: 'Most of the time you do nothing: the vault starts with your computer and works in the background. This is the little you will actually do.',
    use_cards: [
      ['Connect a phone or a laptop',
       'On your computer you ask for a code; on the device you scan or paste it. The device shows six digits and you type them on the computer. That back-and-forth is what keeps anyone else out: approving requires holding the device.'],
      ['See who is connected',
       'Your devices page lists every device, what each one can do and which one is in charge. From there you take permissions away or remove one entirely.'],
      ['If you lose a device',
       'You disconnect it and it stops working: the vault will not sign for it again and, next time it turns on, it wipes what it had of your account.'],
      ['Keep several accounts',
       'You can keep more than one account on the same computer (personal and work, say). They run at the same time and cannot see each other.'],
      ['Set a password',
       'Optional. It stops someone sitting at your computer from changing your account. It does not protect the disk, and your devices keep working with it on.'],
    ],
    use_warn_t: 'The most important thing to know',
    use_warn_b: 'Your account lives on this computer and nowhere else. There is no copy of ours and no way to recover it: if you lose the machine without having connected another vault first, you lose the account. That is the price of it being truly yours, and we would rather tell you than promise a rescue that does not exist.',
    use_cmds_t: 'The commands, if you are at home in a terminal',
    use_cmds: [
      ['dotrino-vault status', 'see if it is running'],
      ['dotrino-vault pair', 'connect a device (shows the code)'],
      ['dotrino-vault approve <code>', 'approve the device with the digits it shows'],
      ['dotrino-vault members', 'who is in your account and what they can do'],
      ['dotrino-vault caps <ID> -firma', 'take a permission away from a device'],
      ['dotrino-vault revoke <nonce>', 'remove a device entirely'],
      ['dotrino-vault activity', 'log: what was signed and who joined'],
      ['dotrino-vault profile ls', 'your accounts on this computer'],
      ['dotrino-vault tui', 'all of the above, on one screen'],
    ],
    use_service_t: 'And the service, if something gets stuck',
    use_more: 'All of this is also on your devices page, no terminal needed.',
    foot_tag: 'Your data, in your place, under your rules.',
    foot_eco: 'Part of the Dotrino ecosystem', foot_src: 'Source', foot_discord: 'Discord',
  },
}
const LANG_KEY = 'vault.lang'
const lang = ref((localStorage.getItem(LANG_KEY) || (navigator.language || 'es').slice(0, 2)) === 'en' ? 'en' : 'es')
const t = computed(() => I18N[lang.value])
const setLang = (l) => { lang.value = l; localStorage.setItem(LANG_KEY, l); document.documentElement.lang = l }

const installCmd = 'tar xzf dotrino-vault-*-linux-x64.tar.gz\ncd dotrino-vault-*-linux-x64\nsh install.sh'
const pairCmd = 'dotrino-vault pair'
const serviceCmd = 'systemctl --user restart dotrino-vault\njournalctl --user -u dotrino-vault -f'

const copied = ref('')
function copy (text, key) {
  navigator.clipboard?.writeText(text).then(() => { copied.value = key; setTimeout(() => (copied.value = ''), 1400) })
}

/* Ruta: la landing en `/` y la consola de dispositivos en `/dispositivos`. El QR de
   `dotrino-vault pair` abre `/dispositivos#vault=<código>` — el código viaja en el
   #fragment, que nunca llega al servidor. */
const view = ref('home')
function routeNow () {
  const p = location.pathname.replace(/\/+$/, '')
  view.value = (/\/dispositivos$/.test(p) || location.hash.includes('#vault=')) ? 'console' : 'home'
}
routeNow()
function go (v, ev) {
  ev?.preventDefault()
  history.pushState(null, '', v === 'console' ? '/dispositivos' : '/')
  routeNow()
}
window.addEventListener('popstate', routeNow)

onMounted(() => { document.documentElement.lang = lang.value })
</script>

<template>
  <div class="page">
    <header class="topbar">
      <a class="brand" href="/"><img src="/icon.svg" alt="" width="30" height="30" /><span>Dotrino&nbsp;Vault</span></a>
      <nav class="navlinks">
        <a v-if="view === 'home'" href="#how">{{ t.nav_how }}</a>
        <a v-if="view === 'home'" href="#download">{{ t.nav_download }}</a>
        <a v-if="view === 'home'" href="#use" data-testid="nav-use">{{ t.nav_use }}</a>
        <a href="/dispositivos" data-testid="nav-devices" @click="go('console', $event)">{{ t.nav_devices }}</a>
        <a v-if="view !== 'home'" href="/" @click="go('home', $event)">{{ t.nav_home }}</a>
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
      <Consola v-if="view === 'console'" :lang="lang" />
      <template v-else>
      <!-- HERO -->
      <section class="hero">
        <p class="kicker">{{ t.hero_kicker }}</p>
        <h1>{{ t.hero_title }}</h1>
        <p class="lead">{{ t.hero_sub }}</p>
        <div class="cta">
          <a class="btn btn-primary" href="#download" data-testid="hero-download">↓ {{ t.hero_download }}</a>
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

        <div class="dl-card">
          <h3>{{ t.dl_deb_t }}</h3>
          <a class="btn btn-primary btn-lg" :href="RELEASES" data-testid="download-deb">↓ {{ t.dl_deb_btn }}</a>
          <p class="dl-note">{{ t.dl_deb_note }}</p>
        </div>

        <div class="dl-card">
          <h3>{{ t.dl_tar_t }}</h3>
          <a class="btn btn-ghost" :href="RELEASES" data-testid="download-tar">↓ {{ t.dl_tar_btn }}</a>
          <div class="codeblock">
            <div class="code-head"><span>{{ t.dl_install_t }}</span>
              <button class="copy" @click="copy(installCmd, 'install')">{{ copied === 'install' ? '✓' : '⧉' }}</button>
            </div>
            <pre><code>{{ installCmd }}</code></pre>
          </div>
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

      <!-- CÓMO SE USA — la landing explicaba cómo descargarla y ahí se acababa. Lo que
           falta después de instalar (conectar aparatos, quitar permisos, varias cuentas)
           y, sobre todo, la consecuencia de perder la máquina, que hay que decir en voz
           alta en vez de esconderla. -->
      <section id="use" class="use" data-testid="use">
        <h2>{{ t.use_title }}</h2>
        <p class="lead">{{ t.use_lead }}</p>

        <div class="use-grid">
          <article v-for="(c, i) in t.use_cards" :key="i" class="use-card">
            <h3>{{ c[0] }}</h3>
            <p>{{ c[1] }}</p>
          </article>
        </div>

        <div class="use-warn" data-testid="use-warn">
          <h3>{{ t.use_warn_t }}</h3>
          <p>{{ t.use_warn_b }}</p>
        </div>

        <p class="use-more">
          <a href="/dispositivos" @click="go('console', $event)">{{ t.use_more }}</a>
        </p>

        <details class="use-cmds">
          <summary>{{ t.use_cmds_t }}</summary>
          <table>
            <tbody>
              <tr v-for="(c, i) in t.use_cmds" :key="i">
                <td><code>{{ c[0] }}</code></td>
                <td>{{ c[1] }}</td>
              </tr>
            </tbody>
          </table>
          <div class="codeblock">
            <div class="code-head"><span>{{ t.use_service_t }}</span>
              <button class="copy" @click="copy(serviceCmd, 'svc')">{{ copied === 'svc' ? '✓' : '⧉' }}</button>
            </div>
            <pre><code>{{ serviceCmd }}</code></pre>
          </div>
        </details>
      </section>
      </template>
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
