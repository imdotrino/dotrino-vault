<script setup>
import { ref, computed, markRaw, onMounted } from 'vue'
import Console from './Console.vue'

const GITHUB = 'https://github.com/imdotrino/dotrino-vault'
const RELEASES = GITHUB + '/releases/latest'
const DISCORD = 'https://discord.gg/D648uq7cth'

/* ---------------- i18n (es/en · tuteo, sin voseo · lenguaje llano) ---------------- */
const I18N = {
  es: {
    nav_how: 'Cómo funciona', nav_download: 'Descargar', nav_devices: 'Mis dispositivos', nav_home: 'Inicio',
    nav_menu: 'Menú', nav_menu_label: 'Navegación',
    hero_kicker: 'Tu bóveda personal · en tu propia máquina',
    hero_title: 'Toda tu información, en un solo lugar seguro',
    hero_sub: 'Tus archivos, tus contactos, tus contraseñas y lo que guardan tus apps, todo junto en una bóveda que vive en tu propia computadora. No en la nube de una empresa: en tu máquina, bajo tu control. Sin anuncios, sin rastreo, sin que nadie venda tus datos.',
    hero_download: 'Descargar gratis', hero_source: 'Ver el código',
    hero_note: 'Instalador para Linux. En Windows y macOS, con un comando o con Docker.',
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
    os: { linux: 'Linux', windows: 'Windows', macos: 'macOS' },
    dl_os_pick: 'Elige tu sistema',
    dl_os_hint: 'Elegimos tu sistema por ti. Si no acertamos, cámbialo aquí.',
    m1_t: '1 · Instalador',
    m1_lead: 'La forma más cómoda: lo instalas y queda funcionando solo, también cuando enciendes la computadora.',
    m1_soon: 'Para este sistema todavía no hay instalador de un clic: está en camino. Las dos formas de abajo ya funcionan y dejan tu bóveda igual de lista.',
    m2_t: '2 · Un comando',
    m2_lead: 'Un comando que se encarga de todo, incluido bajar lo que haga falta. No pide permisos de administrador ni instala nada en el sistema.',
    m2_tui: 'O con la pantalla de control incluida, que es lo más cómodo: te enseña tus dispositivos y ahí mismo apruebas el que se conecta, sin tener que abrir otra ventana ni recordar comandos.',
    m2_note: 'Deja la ventana abierta: mientras esté abierta, tu bóveda está funcionando.',
    m3_t: '3 · Docker',
    m3_tui_tag: 'con pantalla de control',
    dl_win_ps: 'PowerShell',
    dl_win_sh: 'Terminal',
    dl_docker_lead: 'Si ya usas Docker, es la forma más limpia: arranca sola con la máquina, se actualiza fácil y no ensucia tu sistema.',
    dl_docker_note: 'No hace falta abrir ningún puerto ni tocar tu router: la bóveda no escucha nada, se conecta ella hacia afuera. Y ojo con una cosa: el volumen ES tu cuenta. Si lo borras, se perdió.',
    m3_desktop: 'Necesitas Docker Desktop instalado. Y ojo con una cosa: el volumen ES tu cuenta. Si lo borras, se perdió. Tampoco hace falta abrir puertos: la bóveda no escucha nada.',
    dl_pair_note: 'Según cómo la hayas instalado, el comando se escribe con un prefijo distinto. Está explicado abajo, en «Cómo se usa».',
    dl_other: 'Las tres formas dejan la misma bóveda: elige la que te resulte más cómoda.',
    nav_use: 'Cómo se usa',
    use_title: 'Cómo se usa, una vez instalada',
    use_lead: 'Casi todo el tiempo no tienes que hacer nada: la bóveda trabaja de fondo. Con el instalador de Linux y con Docker arranca sola cada vez que enciendes la computadora; si la levantaste con el comando de Windows o macOS, funciona mientras dejes esa ventana abierta. Esto es lo poco que sí harás alguna vez.',
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
    use_tui_t: 'La pantalla de control (y en Windows, todo en una ventana)',
    use_tui_b: 'Hay una interfaz de terminal a pantalla completa donde ves tus dispositivos, apruebas los que se conectan y cambias permisos, sin acordarte de ningún comando. En Windows y macOS, donde la bóveda ocupa la ventana en la que la arrancaste, puedes abrir las dos a la vez:',
    use_tui_alt: 'Si la bóveda ya está corriendo en otra ventana, ahí abres solo la pantalla:',
    use_tui_path: 'En Windows, si el instalador te bajó Node, una ventana NUEVA no lo encuentra. Pega esto antes:',
    use_cmds_how: 'Cómo escribirlos depende de cómo la instalaste:',
    use_cmds_linux: 'Con el instalador de Linux, tal cual.',
    use_cmds_npx: 'Si la levantaste con el comando (Windows o macOS), antepón <code>npx -p @dotrino/vaultd</code>.',
    use_cmds_docker: 'Con Docker, antepón <code>docker exec -it dotrino-vault</code>.',
    use_service_t: 'Arrancar, parar y ver qué pasa',
    use_more: 'Todo esto también está en tu página de dispositivos, sin terminal.',
    foot_tag: 'Tu información, en tu lugar, bajo tus reglas.',
    foot_eco: 'Parte del ecosistema Dotrino', foot_src: 'Código', foot_discord: 'Discord',
  },
  en: {
    nav_how: 'How it works', nav_download: 'Download', nav_devices: 'My devices', nav_home: 'Home',
    nav_menu: 'Menu', nav_menu_label: 'Navigation',
    hero_kicker: 'Your personal vault · on your own machine',
    hero_title: 'All your information, in one safe place',
    hero_sub: 'Your files, your contacts, your passwords and whatever your apps save, all together in a vault that lives on your own computer. Not on a company’s cloud: on your machine, under your control. No ads, no tracking, nobody selling your data.',
    hero_download: 'Download free', hero_source: 'View the code',
    hero_note: 'Installer for Linux. On Windows and macOS, with one command or with Docker.',
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
    os: { linux: 'Linux', windows: 'Windows', macos: 'macOS' },
    dl_os_pick: 'Pick your system',
    dl_os_hint: 'We picked your system for you. If we got it wrong, change it here.',
    m1_t: '1 · Installer',
    m1_lead: 'The most comfortable way: you install it and it keeps running on its own, including when you turn the computer on.',
    m1_soon: 'There is no one-click installer for this system yet: it is on the way. The two ways below already work and leave your vault just as ready.',
    m2_t: '2 · One command',
    m2_lead: 'One command that takes care of everything, including downloading whatever is missing. It does not ask for admin rights and installs nothing system-wide.',
    m2_tui: 'Or with the control screen included, which is the most comfortable: it shows your devices and you approve the one connecting right there, without opening another window or remembering commands.',
    m2_note: 'Leave the window open: while it is open, your vault is running.',
    m3_t: '3 · Docker',
    m3_tui_tag: 'with control screen',
    dl_win_ps: 'PowerShell',
    dl_win_sh: 'Terminal',
    dl_docker_lead: 'If you already use Docker, it is the cleanest way: it starts with the machine, updates easily and does not touch your system.',
    dl_docker_note: 'No ports to open and nothing to touch on your router: the vault listens to nothing, it connects outward. And one thing to keep in mind: the volume IS your account. If you delete it, it is gone.',
    m3_desktop: 'You need Docker Desktop installed. And one thing to keep in mind: the volume IS your account. If you delete it, it is gone. No ports to open either: the vault listens to nothing.',
    dl_pair_note: 'Depending on how you installed it, the command takes a different prefix. It is explained below, under “How to use it”.',
    dl_other: 'All three ways leave you the same vault: pick whichever suits you.',
    nav_use: 'How to use it',
    use_title: 'How to use it, once installed',
    use_lead: 'Most of the time you do nothing: the vault works in the background. With the Linux installer and with Docker it starts on its own every time you turn the computer on; if you launched it with the Windows or macOS command, it runs while you leave that window open. This is the little you will actually do.',
    use_cards: [
      ['Connect a phone or a laptop',
       'On your computer you ask for a code; on the device you scan or paste it. The device shows six digits and you type them on the computer. That back-and-forth is what keeps anyone else out: approving requires holding the device.'],
      ['See who is connected',
       'Your devices page lists every device, what each one can do and which one is the Master. From there you take permissions away or remove one entirely.'],
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
    use_tui_t: 'The control screen (and on Windows, everything in one window)',
    use_tui_b: 'There is a full-screen terminal interface where you see your devices, approve the ones connecting and change permissions, without remembering any command. On Windows and macOS, where the vault takes over the window you started it in, you can open both at once:',
    use_tui_alt: 'If the vault is already running in another window, there you open just the screen:',
    use_tui_path: 'On Windows, if the installer downloaded Node for you, a NEW window will not find it. Paste this first:',
    use_cmds_how: 'How you type them depends on how you installed it:',
    use_cmds_linux: 'With the Linux installer, just as they are.',
    use_cmds_npx: 'If you launched it with the command (Windows or macOS), prefix them with <code>npx -p @dotrino/vaultd</code>.',
    use_cmds_docker: 'With Docker, prefix them with <code>docker exec -it dotrino-vault</code>.',
    use_service_t: 'Starting, stopping and seeing what is going on',
    use_more: 'All of this is also on your devices page, no terminal needed.',
    foot_tag: 'Your data, in your place, under your rules.',
    foot_eco: 'Part of the Dotrino ecosystem', foot_src: 'Source', foot_discord: 'Discord',
  },
}
/* Idioma compartido con el ecosistema: el <dotrino-topbar> persiste en
   'dotrino.lang', así que la app usa la MISMA clave. Migramos una sola vez
   la preferencia vieja ('vault.lang') para no resetear a quien ya eligió. */
const LANG_KEY = 'dotrino.lang'
const LEGACY_KEY = 'vault.lang'

function readLang () {
  try {
    const legacy = localStorage.getItem(LEGACY_KEY)
    if (legacy === 'es' || legacy === 'en') {
      if (!localStorage.getItem(LANG_KEY)) localStorage.setItem(LANG_KEY, legacy)
      localStorage.removeItem(LEGACY_KEY)
    }
  } catch {}
  try {
    const saved = localStorage.getItem(LANG_KEY)
    if (saved === 'es' || saved === 'en') return saved
  } catch {}
  return (navigator.language || 'es').slice(0, 2) === 'en' ? 'en' : 'es'
}

const lang = ref(readLang())
const t = computed(() => I18N[lang.value])
const setLang = (l) => {
  if (l !== 'es' && l !== 'en') return
  lang.value = l
  try { localStorage.setItem(LANG_KEY, l) } catch {}
  document.documentElement.lang = l
}

const installCmd = 'tar xzf dotrino-vault-*-linux-x64.tar.gz\ncd dotrino-vault-*-linux-x64\nsh install.sh'
const pairCmd = 'dotrino-vault pair'
// Instalador universal del ecosistema (dotrino-home/public/install.{ps1,sh}): asegura
// Node 20+ —lo baja LOCAL, sin admin— y corre el paquete. Es la vía probada en Windows.
const winPsCmd = '& ([scriptblock]::Create((irm https://install.dotrino.com/install.ps1))) @dotrino/vaultd'
const winShCmd = 'curl -fsSL https://install.dotrino.com/install.sh | sh -s -- @dotrino/vaultd'
const npxCmd = 'npx -y @dotrino/vaultd'
// La bóveda Y su pantalla de control en la misma ventana: es lo que hace falta donde no
// queda como servicio (Windows, macOS), porque si no hacen falta dos ventanas.
const tuiJuntoCmd = 'npx -y @dotrino/vaultd --tui'
const tuiSoloCmd = 'npx -y -p @dotrino/vaultd dotrino-vault tui'
// El instalador pasa lo que le sigue al paquete, así que la bóveda CON su pantalla de
// control cabe en el mismo comando de instalar: nada de instalar y luego averiguar.
const winPsTuiCmd = '& ([scriptblock]::Create((irm https://install.dotrino.com/install.ps1))) @dotrino/vaultd --tui'
const winShTuiCmd = 'curl -fsSL https://install.dotrino.com/install.sh | sh -s -- @dotrino/vaultd --tui'
const winPathCmd = '$node = (Get-ChildItem "$env:USERPROFILE\\.dotrino" -Directory -Filter \'node-*-win-*\').FullName\n$env:Path = "$node;$env:Path"'

/* Pestañas por sistema: las tres vías existen para los tres, así que mostrarlas todas
   juntas era la misma página tres veces. Se adivina el sistema y se puede cambiar. */
const OSES = ['linux', 'windows', 'macos']
function guessOs () {
  const ua = (navigator.userAgent || '') + ' ' + (navigator.platform || '')
  if (/Win/i.test(ua)) return 'windows'
  if (/Mac|iPhone|iPad/i.test(ua)) return 'macos'
  return 'linux'
}
const os = ref(guessOs())
const dockerCmd = [
  'docker volume create dotrino-vault',
  'docker run -d --name dotrino-vault --restart unless-stopped \\',
  '  -v dotrino-vault:/data ghcr.io/imdotrino/dotrino-vault',
  '',
  '# conectar un aparato:',
  'docker exec -it dotrino-vault dotrino-vault pair'
].join('\n')
const serviceCmd = [
  '# Linux (instalador)',
  'systemctl --user restart dotrino-vault',
  'journalctl --user -u dotrino-vault -f',
  '',
  '# Docker',
  'docker restart dotrino-vault',
  'docker logs -f dotrino-vault',
  '',
  '# Windows o macOS (el comando): cierra esa ventana y vuelve a correrlo'
].join('\n')

const copied = ref('')
function copy (text, key) {
  navigator.clipboard?.writeText(text).then(() => { copied.value = key; setTimeout(() => (copied.value = ''), 1400) })
}

/* Ruta: la landing en `/` y la página de dispositivos en `/devices`, con `/d`
   como atajo. El QR de `dotrino-vault pair` abre `/d#v=<invitación>` — la forma corta
   existe porque cada carácter del enlace son módulos del QR, y los módulos son filas
   de terminal. `/dispositivos` fue la ruta canónica y sigue respondiendo: hay
   invitaciones impresas y enlaces guardados con esa forma, y romperlos no arregla nada. En los dos casos la invitación viaja en el #fragment, que nunca
   llega al servidor. */
const view = ref('home')
function routeNow () {
  const p = location.pathname.replace(/\/+$/, '')
  const invited = location.hash.includes('#vault=') || location.hash.includes('#v=')
  // `/d` es SOLO emparejar (es la dirección corta del QR) y `/devices` SOLO administrar:
  // una pantalla es informativa o administrativa, y emparejar es un proceso con su propia
  // pantalla. Una invitación en la URL manda: llegues por donde llegues, se empareja.
  if (/\/d$/.test(p) || invited) view.value = 'pair'
  else if (/\/(devices|dispositivos)$/.test(p)) view.value = 'console'
  else view.value = 'home'
}
routeNow()
/**
 * Baja a una sección SIN tocar el hash.
 *
 * Un `href="#how"` normal cambia el hash, y eso dispara `popstate`. La capa de «volver»
 * del topbar (el pilar de navegación, que es lo que hace funcionar el botón físico de
 * Android y el gesto de iOS) lo lee como «el usuario pulsó atrás» y se va a `home` — que
 * aquí acababa en `about:blank`. O sea: en el menú, «Cómo funciona» te sacaba de la
 * página. Con el header hecho a mano no pasaba porque no había capa de volver.
 *
 * El `href` se queda por accesibilidad y para poder abrir en pestaña nueva; el
 * desplazamiento lo hacemos nosotros.
 */
function goTo (id, ev) {
  const target = document.getElementById(id)
  if (!target) return
  ev?.preventDefault()
  target.scrollIntoView({ behavior: 'smooth', block: 'start' })
}

function go (v, ev) {
  ev?.preventDefault()
  history.pushState(null, '', v === 'console' ? '/devices' : '/')
  routeNow()
}
window.addEventListener('popstate', routeNow)

/**
 * El topbar es el DUEÑO del modal de perfil (§6.1): se le pasa la identidad y él abre
 * `<dotrino-profile mode="self">` con el avatar del perfil activo. Va `markRaw`: un `ref`
 * de Vue envuelve el objeto en un Proxy reactivo y entonces el `postMessage` al iframe
 * de identidad falla con «could not be cloned».
 */
const topbar = ref(null)
const onTopbarLang = (e) => { if (e.detail?.lang) setLang(e.detail.lang) }

onMounted(async () => {
  document.documentElement.lang = lang.value
  try {
    const { Identity } = await import('@dotrino/identity')
    if (topbar.value) topbar.value.identity = markRaw(await Identity.connect())
  } catch (_) { /* sin identidad el botón sigue estando: abre y ofrece crearla */ }
})
</script>

<template>
  <div class="page">
    <dotrino-topbar
      ref="topbar"
      brand="Dotrino Vault"
      icon="/icon.svg"
      brand-href="/"
      profile
      support-repo="imdotrino/dotrino-vault"
      support-discord="https://discord.gg/D648uq7cth"
      :lang="lang"
      @dotrino-lang="onTopbarLang"
    >
      <a v-if="view === 'home'" href="#how" @click="goTo('how', $event)">{{ t.nav_how }}</a>
      <a v-if="view === 'home'" href="#download" @click="goTo('download', $event)">{{ t.nav_download }}</a>
      <a v-if="view === 'home'" href="#use" data-testid="nav-use" @click="goTo('use', $event)">{{ t.nav_use }}</a>
      <a href="/devices" data-testid="nav-devices" :class="{ on: view === 'console' }" @click="go('console', $event)">{{ t.nav_devices }}</a>
      <a v-if="view !== 'home'" href="/" data-testid="nav-mobile-home" @click="go('home', $event)">{{ t.nav_home }}</a>
    </dotrino-topbar>

    <main>
      <Console v-if="view === 'console' || view === 'pair'" :lang="lang" :mode="view === 'pair' ? 'pair' : 'console'" />
      <template v-else>
      <!-- HERO -->
      <section class="hero">
        <p class="kicker">{{ t.hero_kicker }}</p>
        <h1>{{ t.hero_title }}</h1>
        <p class="lead">{{ t.hero_sub }}</p>
        <div class="cta">
          <a class="btn btn-primary" href="#download" data-testid="hero-download" @click="goTo('download', $event)">↓ {{ t.hero_download }}</a>
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

        <div class="os-tabs" role="group" :aria-label="t.dl_os_pick">
          <button v-for="o in OSES" :key="o" :class="{ on: os === o }"
                  :data-testid="'os-' + o" @click="os = o">{{ t.os[o] }}</button>
        </div>
        <p class="os-hint">{{ t.dl_os_hint }}</p>

        <!-- 1 · Instalador -->
        <div class="dl-card" data-testid="m-installer">
          <h3>{{ t.m1_t }}</h3>
          <template v-if="os === 'linux'">
            <p class="dl-note m1-lead">{{ t.m1_lead }}</p>
            <a class="btn btn-primary btn-lg" :href="RELEASES" data-testid="download-deb">↓ {{ t.dl_deb_btn }}</a>
            <p class="dl-note">{{ t.dl_deb_note }}</p>
            <h4 class="sub">{{ t.dl_tar_t }}</h4>
            <a class="btn btn-ghost" :href="RELEASES" data-testid="download-tar">↓ {{ t.dl_tar_btn }}</a>
            <div class="codeblock">
              <div class="code-head"><span>{{ t.dl_install_t }}</span>
                <button class="copy" @click="copy(installCmd, 'install')">{{ copied === 'install' ? '✓' : '⧉' }}</button>
              </div>
              <pre><code>{{ installCmd }}</code></pre>
            </div>
            <p class="warn">{{ t.dl_warn }}</p>
          </template>
          <p v-else class="dl-note" data-testid="m-installer-soon">{{ t.m1_soon }}</p>
        </div>

        <!-- 2 · Un comando (mismo instalador universal del ecosistema en los tres) -->
        <div class="dl-card" data-testid="m-command">
          <h3>{{ t.m2_t }}</h3>
          <p class="dl-note m1-lead">{{ t.m2_lead }}</p>
          <div class="codeblock">
            <div class="code-head"><span>{{ os === 'windows' ? t.dl_win_ps : t.dl_win_sh }}</span>
              <button class="copy" @click="copy(os === 'windows' ? winPsCmd : winShCmd, 'cmd')">{{ copied === 'cmd' ? '✓' : '⧉' }}</button>
            </div>
            <pre><code>{{ os === 'windows' ? winPsCmd : winShCmd }}</code></pre>
          </div>
          <div class="codeblock">
            <div class="code-head"><span>Node ≥ 20</span>
              <button class="copy" @click="copy(npxCmd, 'npx')">{{ copied === 'npx' ? '✓' : '⧉' }}</button>
            </div>
            <pre><code>{{ npxCmd }}</code></pre>
          </div>
          <p class="dl-note m1-lead">{{ t.m2_tui }}</p>
          <div class="codeblock">
            <div class="code-head"><span>{{ os === 'windows' ? t.dl_win_ps : t.dl_win_sh }} · {{ t.m3_tui_tag }}</span>
              <button class="copy" @click="copy(os === 'windows' ? winPsTuiCmd : winShTuiCmd, 'cmdtui')">{{ copied === 'cmdtui' ? '✓' : '⧉' }}</button>
            </div>
            <pre><code>{{ os === 'windows' ? winPsTuiCmd : winShTuiCmd }}</code></pre>
          </div>
          <p class="dl-note">{{ t.m2_note }}</p>
        </div>

        <!-- 3 · Docker (idéntico en los tres; solo cambia la nota) -->
        <div class="dl-card" data-testid="m-docker">
          <h3>{{ t.m3_t }}</h3>
          <p class="dl-note m1-lead">{{ t.dl_docker_lead }}</p>
          <div class="codeblock">
            <div class="code-head"><span>Docker</span>
              <button class="copy" @click="copy(dockerCmd, 'docker')">{{ copied === 'docker' ? '✓' : '⧉' }}</button>
            </div>
            <pre><code>{{ dockerCmd }}</code></pre>
          </div>
          <p class="dl-note">{{ os === 'linux' ? t.dl_docker_note : t.m3_desktop }}</p>
        </div>

        <div class="codeblock">
          <div class="code-head"><span>{{ t.dl_pair_t }}</span>
            <button class="copy" @click="copy(pairCmd, 'pair')">{{ copied === 'pair' ? '✓' : '⧉' }}</button>
          </div>
          <pre><code>{{ pairCmd }}</code></pre>
        </div>
        <p class="dl-note">{{ t.dl_pair_note }}</p>

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

        <div class="use-tui" data-testid="use-tui">
          <h3>{{ t.use_tui_t }}</h3>
          <p>{{ t.use_tui_b }}</p>
          <div class="codeblock">
            <div class="code-head"><span>Windows · macOS · Linux</span>
              <button class="copy" @click="copy(tuiJuntoCmd, 'tuij')">{{ copied === 'tuij' ? '✓' : '⧉' }}</button>
            </div>
            <pre><code>{{ tuiJuntoCmd }}</code></pre>
          </div>
          <p>{{ t.use_tui_alt }}</p>
          <div class="codeblock">
            <div class="code-head"><span>{{ t.dl_win_sh }}</span>
              <button class="copy" @click="copy(tuiSoloCmd, 'tuis')">{{ copied === 'tuis' ? '✓' : '⧉' }}</button>
            </div>
            <pre><code>{{ tuiSoloCmd }}</code></pre>
          </div>
          <p>{{ t.use_tui_path }}</p>
          <div class="codeblock">
            <div class="code-head"><span>PowerShell</span>
              <button class="copy" @click="copy(winPathCmd, 'winpath')">{{ copied === 'winpath' ? '✓' : '⧉' }}</button>
            </div>
            <pre><code>{{ winPathCmd }}</code></pre>
          </div>
        </div>

        <p class="use-more">
          <a href="/devices" @click="go('console', $event)">{{ t.use_more }}</a>
        </p>

        <details class="use-cmds">
          <summary>{{ t.use_cmds_t }}</summary>
          <p class="cmds-how">{{ t.use_cmds_how }}</p>
          <ul class="cmds-how">
            <li>{{ t.use_cmds_linux }}</li>
            <li v-html="t.use_cmds_npx"></li>
            <li v-html="t.use_cmds_docker"></li>
          </ul>
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
