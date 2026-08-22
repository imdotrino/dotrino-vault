<script setup>
/**
 * Consola «Dónde vive tu perfil» — la ÚNICA pantalla del ecosistema donde se gestionan
 * los dispositivos de un perfil. Muestra el acta: quién es del perfil, qué puede hacer
 * cada uno y quién manda (el master, el único que puede cambiarla).
 *
 * Cero criptografía aquí dentro: todo va por RPC al iframe de identidad
 * (`@dotrino/identity`), que es quien custodia la llave y sella el acta.
 * Diseño: dotrino-vault/docs/acta-de-perfil.md
 */
import { ref, computed, markRaw, onMounted, onBeforeUnmount } from 'vue'
import { Identity } from '@dotrino/identity'
import jsQR from 'jsqr'
import { qrSvg } from './qr.js'
import Vars from './Vars.vue'
import { parseInvite, inviteUrl } from '../../lib/src/invite.js'

/**
 * `mode`:
 *   · `console` (`/devices`) — la pantalla ADMINISTRATIVA: el acta, los miembros, los
 *     permisos, la bóveda de este aparato. Ignora cualquier invitación que venga en la
 *     URL: aquí no se empareja.
 *   · `pair` (`/d`)          — SOLO emparejar. Es la dirección corta a la que apunta el
 *     QR, y lo que hace es una cosa y nada más. Mezclarla con la consola era lo que
 *     hacía que llegar por un QR te dejara delante de una pantalla llena de botones sin
 *     saber en cuál estabas.
 */
const props = defineProps({
  lang: { type: String, default: 'es' },
  mode: { type: String, default: 'console' }
})
const pairOnly = computed(() => props.mode === 'pair')

const T = {
  es: {
    title: 'Dónde vive tu perfil',
    lead: 'Estos son los dispositivos de tu perfil y lo que puede hacer cada uno. El acta la firma uno solo —el Master—, y ninguna llave sale nunca de su dispositivo.',
    loading: 'Cargando…',
    err_connect: 'No se pudo abrir tu identidad. Recarga la página e inténtalo otra vez.',
    profile: 'Perfil', version: 'Versión del acta', master: 'Master',
    members: 'Dispositivos', me: 'este dispositivo', is_master: 'Master',
    caps: { sign: 'Firma por ti', store: 'Guarda tu contenido', read: 'Lee tu contenido', secrets: 'Lee sus propias claves', admin: 'Administra el perfil' },
    service: 'servicio',
    service_note: 'Un servicio solo puede abrir las claves de su propio nombre: no ve nada más de lo tuyo.',
    debt_t: 'Este aparato todavía no puede abrir:',
    debt_b: 'se le entregan solas cuando abras la bóveda en su máquina, o en cuanto otro aparato del mismo servicio esté encendido.',
    caps_none: 'sin permisos',
    info_label: 'Qué es esto',
    sync_err_t: 'No se pudo hablar con tu bóveda',
    // El reintento es AUTOMÁTICO: nadie tiene que pulsar nada para que una lista se ponga
    // al día. Lo único que se enseña es el estado — cuándo se confirmó por última vez.
    sync_checking: 'comprobando con tu bóveda…',
    sync_at: (h) => `confirmado con tu bóveda a las ${h}`,
    sync_stale: 'sin confirmar con tu bóveda',
    // Este aparato guarda el acta de una bóveda con la que ya no puede hablar. No es un
    // fallo de red, y por eso se callaba: se tomaba por «todavía no está en ninguna».
    nolink_t: 'Este dispositivo ya no puede hablar con tu bóveda',
    nolink_b: 'No le queda conexión guardada, así que lo de abajo es una copia vieja y no hay forma de actualizarla desde aquí. Conéctalo otra vez.',
    sync_err_b: 'Lo de abajo es la última copia que tiene este dispositivo, puede estar desfasada. ¿Está encendida la bóveda?',
    solo_warn_t: 'Solo tienes este dispositivo',
    solo_warn_b: 'Si lo pierdes, pierdes el perfil: no hay forma de recuperarlo. Conecta al menos otro dispositivo o tu bóveda.',
    not_master_t: 'Este dispositivo no es el Master',
    not_master_b: 'Los cambios (conectar, quitar o cambiar permisos) se hacen desde el Master.',
    not_master_admin_b: 'Pero puede administrar: conectar y quitar dispositivos desde aquí. Cambiar permisos y pasar el Master a otro siguen siendo cosa del Master.',
    act_add: 'Conectar un dispositivo', act_remove: 'Quitar', act_handover: 'Que mande este',
    act_renounce: 'Que este dispositivo deje de firmar por su cuenta', act_renounced: 'Ya no firma',
    // Se dice lo que PASA, incluido el límite: a un aparato apagado no le llega nada. Lo
    // único que le borra la cuenta es el aviso firmado, y ese necesita que se conecte.
    // Callarlo hacía creer que quitar borra al instante en el otro lado, y no.
    confirm_remove: '¿Quitar este dispositivo del perfil? Dejará de entrar y no podrá abrir lo que guardes a partir de ahora. Si está apagado, lo suyo sigue ahí hasta que se conecte: es entonces cuando se le borra.',
    // Quitarse a UNO MISMO no es lo mismo y no puede preguntarse igual: aquí se acaba la
    // cuenta en este aparato, y eso hay que decirlo antes, no descubrirlo después.
    confirm_remove_me: 'Vas a quitar ESTE dispositivo. Aquí se cierra la cuenta: dejará de firmar, de leer y de guardar, y lo que tenga guardado se borra. Para volver a usarla habría que conectarlo otra vez desde tu bóveda.',
    // Estado de cada aparato: no es documentación, es el dato que hace falta para decidir.
    dev_until: (d) => 'conectado hasta el ' + d,
    dev_nocert: 'sin acceso',
    dev_nocert_b: 'Está en tu lista pero ya no puede entrar. Si ya no lo usas, quítalo; si lo sigues usando, conéctalo otra vez.',
    // Este dispositivo salió del perfil (lo quitaron aquí o desde otro lado).
    gone_t: 'Este dispositivo ya no está en el perfil',
    gone_b: 'Se quitó del perfil y la cuenta se borró de este aparato con lo que tenía guardado.',
    // Qué queda al recargar lo decide el arranque (otra cuenta tuya, o una nueva si esa
    // era la única), así que aquí no se promete cuál: se dice que recargues.
    gone_reload: 'Recarga y seguirás con otra de tus cuentas; si esa era la única, se estrenará una nueva.',
    gone_reload_go: 'Recargar',
    gone_stuck: 'La cuenta no se pudo borrar de este aparato:',
    gone_go: 'Conectar este dispositivo',
    // La bóveda nos rechaza pero SIN aviso firmado: se cuenta, no se borra nada.
    rejected_t: 'Tu bóveda está rechazando a este dispositivo',
    rejected_b: 'Puede que lo hayan quitado del perfil. Aquí no se borra nada por un mensaje suelto: enciende tu bóveda y vuelve a abrir esta página para saberlo con certeza.',
    confirm_handover: 'A partir de ahora mandará ese dispositivo y este dejará de poder cambiar el acta. ¿Seguir?',
    confirm_renounce: 'Este dispositivo dejará de firmar con su propia llave: a partir de ahora le pedirá cada firma a tu bóveda. Podrás devolvérselo desde el Master. ¿Seguir?',
    yes: 'Sí, hazlo', cancel: 'Cancelar',
    // --- Pantalla del PROCESO de conectar (se lleva la página entera) ---
    flow_connecting: 'Hablando con tu bóveda…',
    flow_connecting_b: 'Un momento. En cuanto responda te daremos un código de seis dígitos.',
    flow_waiting: 'Esperando a que lo apruebes…',
    pair_code_cli: 'Si tu bóveda es la de la computadora:',
    flow_close: 'Ver mis dispositivos',
    flow_failed: 'No se pudo conectar',
    pair_t: 'Conectar este dispositivo a una bóveda',
    pair_b: 'Escanea el código que te muestra tu bóveda, o pégalo aquí.',
    pair_scan: 'Escanear con la cámara', pair_file: 'Abrir imagen o archivo',
    pair_paste: 'Pegar el código', pair_go: 'Conectar',
    pair_bad: 'Ese código no vale. Copia otra vez el que te muestra tu bóveda.',
    pair_old: 'Ese código es de una versión antigua. Genera uno nuevo en tu bóveda.',
    pair_wait: 'Conectando… espera un momento.',
    pair_code_t: 'Escribe este código en tu bóveda',
    pair_code_b: 'Ábrela y teclea estos seis dígitos para aprobar la conexión. Nadie más los conoce.',
    pair_done: 'Listo, este dispositivo ya está conectado.',
    adopt_done: 'Listo, tu cuenta ya vive en tu bóveda.',
    adopt_done_b: 'Sigue siendo la misma cuenta de siempre: los mismos contactos, lo mismo firmado, nada que volver a hacer. Lo que cambió es que ahora la guarda tu bóveda, que pasa a ser el Master, y este aparato es uno más de los que la usan.',
    pair_new_account: 'Se creará aquí una cuenta nueva: la de tu bóveda. La que estás usando ahora no se toca.',
    ann_t: 'Esto es lo que quiere hacer tu bóveda',
    ann_join_h: (n) => n ? `Crear en este dispositivo una cuenta nueva: «${n}», la de tu bóveda.` : 'Crear en este dispositivo una cuenta nueva: la de tu bóveda.',
    ann_join_c: 'La cuenta que estás usando ahora no se toca. Al terminar tendrás dos y podrás cambiar entre ellas cuando quieras.',
    ann_adopt_h: (n) => n ? `Guardar y administrar tu cuenta «${n}»: pasaría a vivir en tu bóveda.` : 'Guardar y administrar la cuenta que usas en este dispositivo.',
    ann_adopt_c: 'Tu cuenta seguiría siendo la misma para todo el mundo, pero a partir de ahí el Master sería tu bóveda: este dispositivo dejaría de ser quien firma los cambios.',
    ann_adopt_no: 'Este dispositivo todavía no sabe entregar su cuenta. Actualiza la página, o elige la otra opción en tu bóveda.',
    ann_go: 'Continuar', ann_cancel: 'Cancelar',
    two_title: 'Ahora tienes dos cuentas en este aparato',
    two_body: 'La que ya usabas sigue intacta, y se agregó la de tu bóveda, que es la que estás usando ahora. Puedes cambiar entre ellas cuando quieras desde el botón de tu foto, arriba.',
    two_del: 'Si no quieres conservar la anterior:',
    two_del_1: 'Abre tu página de perfil.',
    two_del_2: 'En «Tus perfiles», pulsa Borrar en la cuenta que no quieras.',
    two_del_3: 'Confirma. Se va con todo lo suyo y no se puede deshacer.',
    two_del_link: 'Abrir mi página de perfil',
    pair_fail: 'No se pudo conectar: ',
    cam_err: 'No se pudo abrir la cámara. Pega el código a mano.',
    no_qr: 'No se encontró ningún código en esa imagen.',
    self_t: 'Que este dispositivo sea la bóveda',
    self_b: 'Otros dispositivos tuyos podrán conectarse a este. Tiene que estar encendido y con la página abierta.',
    self_on: 'Encendida', self_off: 'Apagada', self_start: 'Encender', self_stop: 'Apagar',
    self_pair: 'Generar código para conectar otro',
    self_pending: 'Un dispositivo quiere conectarse',
    self_code_ph: 'Los 6 dígitos que muestra',
    self_approve: 'Aprobar', self_reject: 'Rechazar',
    // --- Administrar la bóveda desde aquí (consola remota) ---
    adm_t: 'Administrar tu bóveda desde aquí',
    adm_b: 'Este dispositivo puede conectar y quitar otros sin que vayas a la computadora donde vive tu bóveda.',
    adm_no_t: 'Este dispositivo solo mira',
    adm_no_b: 'Para que pueda conectar y quitar dispositivos, dale el permiso en la computadora de tu bóveda: dotrino-vault caps <ID> +administra',
    adm_pair: 'Conectar un dispositivo',
    // El QR solo sirve si el otro aparato tiene cámara y está delante. El enlace sirve
    // siempre, y es lo mismo: la misma invitación, escrita.
    invite_url: 'O pásale este enlace:',
    invite_copy: 'Copiar enlace', invite_copied: 'Copiado',
    adm_pending: 'Un dispositivo quiere conectarse',
    adm_code_ph: 'Los 6 dígitos que muestra',
    adm_approve: 'Aprobar', adm_reject: 'Rechazar',
    // VARIABLES DE ENTORNO. Lenguaje llano (CONVENCIONES §9.1): no se dice «secreto de
    // servicio» ni «namespace», se dice qué es y quién lo puede ver.
    var_t: 'Variables de tus aplicaciones',
    var_b: 'Son los datos de configuración que tus aplicaciones necesitan para funcionar (una clave, una dirección, un número). Los guarda tu bóveda. Un grupo lo usan todas las máquinas; las de un servicio están en su fila, arriba, y solo las ve él. Una variable privada no enseña su valor aquí —no sale de la computadora de tu bóveda— pero le puedes dar uno nuevo igual.',
    var_shared: 'la usan todas las máquinas',
    pend_t: 'Hay variables sin entregar',
    pend_b: 'Estos grupos no han podido entregar su llave, así que sus aparatos no están leyendo sus variables. Se arregla guardando aquí cualquier variable de ese grupo con la contraseña.',
    pend_rotate: 'salió un aparato del grupo',
    pend_rewrap: 'entró un aparato al grupo',
    nopwd_t: 'Esta bóveda no tiene contraseña',
    nopwd_b: 'Sus variables privadas se abren con una llave de la computadora donde vive la bóveda, y esa llave está en ese mismo disco: quien copie el disco las abre. Ponle una contraseña en esa computadora.',
    var_dev_t: 'Sus variables',
    var_dev_hint: 'Las variables de un aparato se ponen en su fila, arriba.',
    var_orphan: 'ya no está en el perfil',
    var_private: 'privada',
    var_save: 'Guardar',
    // UN solo botón: se edita todo y se confirma una vez. Cada guardado reinicia la
    // aplicación que usa esas variables, así que guardar de una en una la reiniciaba
    // por cada una, y arrancaba con la configuración a medias.
    var_save_n: (n) => `Guardar ${n} cambio${n === 1 ? '' : 's'}`,
    var_save_hint: 'Se guardan juntas: la aplicación se reinicia una sola vez.',
    var_pending: 'sin guardar',
    var_incomplete: 'Hay una fila sin nombre o sin valor.',
    var_show: 'Ver',
    var_hide: 'Ocultar',
    var_versions: 'Versiones',
    var_no_versions: 'No hay versiones anteriores.',
    var_restore: 'Restaurar',
    var_by: (id) => `desde ${id}`,
    var_by_vault: 'desde la máquina de la bóveda',
    var_group_new: 'Grupo nuevo',
    var_scope_ph: 'nombre del grupo (p. ej. proxy)',
    var_key_ph: 'NOMBRE_DE_LA_VARIABLE',
    // Lo único que queda del cuadro de texto de antes: decir dónde se pega el archivo
    // entero. La fila nueva aparece sola al escribir, así que no hay botón que explicar.
    var_paste_hint: 'Para cargar varias de una vez, pega tu configuración (NOMBRE=valor, una por línea) en el campo del nombre.',
    var_value_ph: 'valor',
    var_private_ask: 'Privada',
    var_paste_err: (e) => ({
      shape: `línea ${e.line}: no tiene la forma NOMBRE=valor`,
      key: `línea ${e.line}: «${e.key}» va en MAYUSCULAS_CON_GUION_BAJO`,
      novalue: `línea ${e.line}: ${e.key} no tiene valor`,
      dup: `línea ${e.line}: ${e.key} ya venía en la línea ${e.first}`,
      empty: 'No hay ninguna variable ahí'
    })[e.code],
    adm_warn: 'Aprueba solo si esos dígitos son los que ves en la pantalla del otro aparato. Nadie debería dictártelos.',
    back: 'Volver'
  },
  en: {
    title: 'Where your profile lives',
    lead: 'These are your profile’s devices and what each one can do. A single device signs the record —the Master— and no key ever leaves its device.',
    loading: 'Loading…',
    err_connect: 'Could not open your identity. Reload the page and try again.',
    profile: 'Profile', version: 'Record version', master: 'Master',
    members: 'Devices', me: 'this device', is_master: 'Master',
    caps: { sign: 'Signs for you', store: 'Stores your content', read: 'Reads your content', secrets: 'Reads its own keys', admin: 'Manages the profile' },
    service: 'service',
    service_note: 'A service can only open the keys under its own name: it sees nothing else of yours.',
    debt_t: 'This device cannot open yet:',
    debt_b: 'it gets them on its own when you open the vault on its machine, or as soon as another device of the same service is up.',
    caps_none: 'no permissions',
    info_label: 'What is this',
    sync_err_t: 'Could not reach your vault',
    sync_checking: 'checking with your vault…',
    sync_at: (h) => `confirmed with your vault at ${h}`,
    sync_stale: 'not confirmed with your vault',
    nolink_t: 'This device can no longer talk to your vault',
    nolink_b: 'It has no saved connection left, so the list below is an old copy and there is no way to update it from here. Connect it again.',
    sync_err_b: 'What you see below is the last copy this device has, and it may be out of date. Is the vault running?',
    solo_warn_t: 'You only have this device',
    solo_warn_b: 'If you lose it, you lose the profile: there is no way to recover it. Connect at least one more device or your vault.',
    not_master_t: 'This device is not the Master',
    not_master_b: 'Changes (connecting, removing or changing permissions) are made from the Master.',
    not_master_admin_b: 'But it can manage: connect and remove devices from here. Changing permissions and passing the Master on are still the Master\u2019s job.',
    act_add: 'Connect a device', act_remove: 'Remove', act_handover: 'Make this one the Master',
    act_renounce: 'Stop this device signing on its own', act_renounced: 'No longer signs',
    confirm_remove: 'Remove this device from the profile? It will no longer get in, and it will not be able to open anything you save from now on. If it is switched off, what it has stays there until it connects: that is when it is erased.',
    confirm_remove_me: 'You are removing THIS device. The account ends here: it will stop signing, reading and storing, and whatever it has saved is erased. To use it again you would have to connect it from your vault.',
    dev_until: (d) => 'connected until ' + d,
    dev_nocert: 'no access',
    dev_nocert_b: 'It is on your list but it can no longer get in. If you do not use it any more, remove it; if you do, connect it again.',
    gone_t: 'This device is no longer in the profile',
    gone_b: 'It was removed from the profile and the account was erased from this device, along with whatever it had saved.',
    gone_reload: 'Reload and you will carry on with another of your accounts; if that was the only one, a new one is created.',
    gone_reload_go: 'Reload',
    gone_stuck: 'The account could not be erased from this device:',
    gone_go: 'Connect this device',
    rejected_t: 'Your vault is turning this device away',
    rejected_b: 'It may have been removed from the profile. Nothing is erased here on the strength of a bare message: turn your vault on and open this page again to know for sure.',
    confirm_handover: 'From now on that device becomes the Master and this one will no longer be able to change the record. Continue?',
    confirm_renounce: 'This device will stop signing with its own key: from now on it will ask your vault for every signature. You can give it back from the Master. Continue?',
    yes: 'Yes, do it', cancel: 'Cancel',
    // --- The pairing PROCESS screen (takes over the whole page) ---
    flow_connecting: 'Talking to your vault…',
    flow_connecting_b: 'One moment. As soon as it answers we will give you a six-digit code.',
    flow_waiting: 'Waiting for you to approve it…',
    pair_code_cli: 'If your vault is the one on your computer:',
    flow_close: 'See my devices',
    flow_failed: 'Could not connect',
    pair_t: 'Connect this device to a vault',
    pair_b: 'Scan the code your vault shows you, or paste it here.',
    pair_scan: 'Scan with the camera', pair_file: 'Open image or file',
    pair_paste: 'Paste the code', pair_go: 'Connect',
    pair_bad: 'That code is not valid. Copy the one your vault shows again.',
    pair_old: 'That code is from an old version. Generate a new one in your vault.',
    pair_wait: 'Connecting… hold on.',
    pair_code_t: 'Type this code in your vault',
    pair_code_b: 'Open it and type these six digits to approve the connection. Nobody else knows them.',
    pair_done: 'Done, this device is connected.',
    adopt_done: 'Done, your account now lives in your vault.',
    adopt_done_b: 'It is the same account as always: same contacts, same signed history, nothing to redo. What changed is that your vault now keeps it and is the Master, and this device is one more that uses it.',
    pair_new_account: 'A new account will be created here: your vault\'s. The one you are using now is left untouched.',
    ann_t: 'This is what your vault wants to do',
    ann_join_h: (n) => n ? `Create a new account on this device: “${n}”, your vault's.` : 'Create a new account on this device: your vault\'s.',
    ann_join_c: 'The account you are using now is left untouched. When it is done you will have two, and you can switch between them any time.',
    ann_adopt_h: (n) => n ? `Keep and manage your account “${n}”: it would move into your vault.` : 'Keep and manage the account you use on this device.',
    ann_adopt_c: 'Your account would stay the same for everyone else, but from then on your vault is the Master: this device would no longer sign its changes.',
    ann_adopt_no: 'This device cannot hand its account over yet. Reload the page, or choose the other option in your vault.',
    ann_go: 'Continue', ann_cancel: 'Cancel',
    two_title: 'You now have two accounts on this device',
    two_body: 'The one you were using is untouched, and your vault\'s was added — that is the one you are using now. You can switch between them any time from your photo button, above.',
    two_del: 'If you do not want to keep the previous one:',
    two_del_1: 'Open your profile page.',
    two_del_2: 'Under “Your profiles”, press Delete on the account you do not want.',
    two_del_3: 'Confirm. It goes with everything in it and cannot be undone.',
    two_del_link: 'Open my profile page',
    pair_fail: 'Could not connect: ',
    cam_err: 'Could not open the camera. Paste the code by hand.',
    no_qr: 'No code found in that image.',
    self_t: 'Make this device the vault',
    self_b: 'Your other devices will be able to connect to this one. It has to be on, with the page open.',
    self_on: 'On', self_off: 'Off', self_start: 'Turn on', self_stop: 'Turn off',
    self_pair: 'Create a code to connect another one',
    self_pending: 'A device wants to connect',
    adm_t: 'Manage your vault from here',
    adm_b: 'This device can connect and remove others without you going to the computer where your vault lives.',
    adm_no_t: 'This device can only look',
    adm_no_b: 'To let it connect and remove devices, grant the permission on your vault computer: dotrino-vault caps <ID> +administra',
    adm_pair: 'Connect a device',
    invite_url: 'Or send it this link:',
    invite_copy: 'Copy link', invite_copied: 'Copied',
    adm_pending: 'A device wants to connect',
    adm_code_ph: 'The 6 digits it shows',
    adm_approve: 'Approve', adm_reject: 'Reject',
    var_t: 'Your apps\u2019 variables',
    var_b: 'These are the settings your apps need to run (a key, an address, a number). Your vault keeps them. A group is used by every machine; a service\u2019s own ones live in its row above and only it can see them. A private variable does not show its value here \u2014it never leaves your vault\u2019s computer\u2014 but you can still give it a new one.',
    var_shared: 'used by every machine',
    pend_t: 'Some variables are not being delivered',
    pend_b: 'These groups could not hand out their key, so their devices are not reading their variables. Save any variable of that group here, with the password, and it is fixed.',
    pend_rotate: 'a device left the group',
    pend_rewrap: 'a device joined the group',
    nopwd_t: 'This vault has no password',
    nopwd_b: 'Its private variables open with a key from the computer where the vault lives, and that key sits on the same disk: whoever copies the disk opens them. Set a password on that computer.',
    var_dev_t: 'Its variables',
    var_dev_hint: 'A device’s variables live in its own row, above.',
    var_orphan: 'no longer in the profile',
    var_private: 'private',
    var_save: 'Save',
    var_save_n: (n) => `Save ${n} change${n === 1 ? '' : 's'}`,
    var_save_hint: 'They are saved together: the app restarts only once.',
    var_pending: 'unsaved',
    var_incomplete: 'A row has no name or no value.',
    var_show: 'Show',
    var_hide: 'Hide',
    var_versions: 'Versions',
    var_no_versions: 'No earlier versions.',
    var_restore: 'Restore',
    var_by: (id) => `from ${id}`,
    var_by_vault: 'from the vault machine',
    var_paste_err: (e) => ({
      shape: `line ${e.line}: not in the form NAME=value`,
      key: `line ${e.line}: "${e.key}" must be UPPERCASE_WITH_UNDERSCORES`,
      novalue: `line ${e.line}: ${e.key} has no value`,
      dup: `line ${e.line}: ${e.key} already came on line ${e.first}`,
      empty: 'There is no variable there'
    })[e.code],
    var_group_new: 'New group',
    var_scope_ph: 'group name (e.g. proxy)',
    var_key_ph: 'VARIABLE_NAME',
    var_paste_hint: 'To load several at once, paste your configuration (NAME=value, one per line) into the name field.',
    var_value_ph: 'value',
    var_private_ask: 'Private',
    adm_warn: 'Approve only if those digits are the ones on the other device screen. Nobody should be reading them out to you.',
    self_code_ph: 'The 6 digits it shows',
    self_approve: 'Approve', self_reject: 'Reject',
    back: 'Back'
  }
}
const t = computed(() => T[props.lang] || T.es)

/**
 * En desarrollo se puede apuntar la identidad a un iframe LOCAL con `?vault=<url>`, para
 * poder probar la consola entera sin salir de la máquina.
 *
 * Solo se acepta si esta página se está sirviendo desde localhost. Es importante: sin ese
 * cerrojo, un enlace del tipo `vault.dotrino.com/dispositivos?vault=…` podría apuntar tu
 * identidad a un iframe ajeno, que es exactamente el ataque que este proyecto evita.
 */
function identityOptions () {
  const local = /^(localhost|127\.0\.0\.1|\[::1\])$/.test(location.hostname)
  if (!local) return {}
  // En localhost usamos el iframe de `/id/` (vite sirve @dotrino/identity con
  // proxy-client actualizado). `?vault=` sigue valiendo para apuntar a otro sitio.
  const url = new URLSearchParams(location.search).get('vault') || `${location.origin}/id/`
  return { vaultUrl: url }
}

const id = ref(null)
const loading = ref(true)
const fatal = ref('')
const record = ref(null)
const members = ref([])
const mine = ref(null)
const msg = ref(null) // { kind:'ok'|'bad'|'info', text }
const busy = ref('')

const isMaster = computed(() => !!mine.value?.isMaster)
/**
 * ¿Este aparato YA vive en una bóveda? Si el que sella el acta es OTRO miembro, la cuenta
 * ya tiene su bóveda y este dispositivo es uno de sus invitados. Entonces no se le ofrece
 * ni «conectarse a una bóveda» (ya lo está) ni «ser la bóveda» (el mando lo tiene otro y
 * traspasarlo no es una casilla): eran dos pasos de alta que se quedaban a la vista para
 * siempre, invitando a hacer algo que no procede.
 */
const alreadyInVault = computed(() => !!record.value && !isMaster.value)
const soloMember = computed(() => members.value.length <= 1)
/**
 * El identificador del perfil es una **pubkey JWK**, no un id corto: recortarla a 8
 * caracteres no la hace legible, la deja pareciendo un error (`{"key_op`). Se enseña su
 * huella, que es la misma que ves al emparejar, en la lista de miembros y en el CLI.
 */
const shortId = (s) => (s || '').slice(0, 8)
const profileIdShort = ref('')
async function computeProfileIdShort () {
  const pub = record.value?.profileId
  if (!pub) { profileIdShort.value = ''; return }
  try {
    const { pubkeyId } = await import('@dotrino/identity/capabilities')
    const h = (await pubkeyId(pub)).slice(0, 8).toUpperCase()
    profileIdShort.value = h.slice(0, 4) + '-' + h.slice(4)
  } catch (_) { profileIdShort.value = shortId(pub) }
}

/** Falla al hablar con la bóveda: se ENSEÑA, no se traga (ver `syncError`). */
const syncError = ref('')
/**
 * SIN CONEXIÓN GUARDADA: este aparato tiene el acta de una bóveda con la que ya no puede
 * hablar (no le queda certificado). Se callaba —se tomaba por «todavía no está en ninguna
 * bóveda»— y la pantalla seguía enseñando la copia vieja como si fuera de ahora: el perfil,
 * el master y sus permisos, todo de un acta de hace semanas. Y sin conexión tampoco puede
 * recibir el aviso firmado que le borraría la cuenta, así que se queda así para siempre.
 */
const notLinked = ref(false)
/** Comprobando contra la bóveda (el botón de actualizar) y cuándo se confirmó por última vez. */
const checking = ref(false)
const checkedAt = ref(0)
/** Copia vieja e incomprobable: hay acta de otro, y no hay con qué preguntarle. */
const staleCopy = computed(() => notLinked.value && !!record.value && !isMaster.value)
const shortTime = (ms) => {
  try { return new Date(ms).toLocaleTimeString(props.lang === 'en' ? 'en-US' : 'es-ES', { hour: '2-digit', minute: '2-digit' }) }
  catch (_) { return '' }
}

/**
 * BOTÓN (i): las explicaciones no se leen, estorban.
 *
 * Esta página es de ADMINISTRACIÓN, no de divulgación —para eso está el home—, así que lo
 * que se ve por defecto son los aparatos y los botones. El porqué de cada sección vive
 * detrás de una (i) y se abre cuando alguien lo busca. Una sola abierta a la vez.
 */
const info = ref('')
const toggleInfo = (k) => { info.value = info.value === k ? '' : k }

/**
 * Los CERTIFICADOS que la bóveda tiene emitidos, agrupados por llave (`sub`).
 *
 * No es otra lista de dispositivos —esa es una sola, el acta— sino el ESTADO de cada uno:
 * hasta cuándo puede entrar. Que estuviera pintado aparte, en su propia sección y con su
 * propio botón «Quitar», es lo que hacía que el mismo aparato saliera dos veces diciendo
 * cosas distintas: arriba como miembro, abajo como papel.
 */
const certBySub = ref(new Map())

function groupCerts (devices) {
  const m = new Map()
  for (const x of (devices || [])) {
    if (!x.sub) continue
    const y = m.get(x.sub)
    if (!y || (x.exp || 0) > (y.exp || 0)) m.set(x.sub, x)
  }
  return m
}

/**
 * REINTENTO AUTOMÁTICO. Que una lista se ponga al día no es trabajo del usuario: si no se
 * pudo confirmar con la bóveda, se vuelve a intentar solo —espaciando los intentos para no
 * castigar a una bóveda apagada—, y además al volver a esta pestaña y al recuperar la red,
 * que es cuando de verdad cambian las cosas.
 */
const RETRY_MS = [3000, 10000, 30000, 60000]
let failures = 0
let retryTimer = null
function scheduleRetry () {
  clearTimeout(retryTimer)
  retryTimer = setTimeout(() => { refresh() }, RETRY_MS[Math.min(failures - 1, RETRY_MS.length - 1)])
}
const onVisible = () => { if (document.visibilityState === 'visible' && failures) refresh() }
const onOnline = () => { if (failures) refresh() }
onMounted(() => {
  document.addEventListener('visibilitychange', onVisible)
  window.addEventListener('online', onOnline)
})
onBeforeUnmount(() => {
  clearTimeout(retryTimer)
  document.removeEventListener('visibilitychange', onVisible)
  window.removeEventListener('online', onOnline)
})

async function refresh () {
  // Si este aparato vive en una bóveda, lo PRIMERO es traerse su acta. Lo que se ve aquí
  // es lo que decidió el dueño en la bóveda —permisos, nombres, quién entró—, no la copia
  // del día que emparejamos. Sin esto la pantalla se quedaba congelada en ese día: el
  // dispositivo renombrado seguía con el nombre viejo y los permisos nuevos no salían.
  checking.value = true
  try {
    const r = await id.value.listVaultDevices()
    certBySub.value = groupCerts(r?.devices)
    syncError.value = ''
    notLinked.value = false
    checkedAt.value = Date.now()
    failures = 0
    clearTimeout(retryTimer)
  } catch (e) {
    // «No emparejado con ninguna bóveda» no siempre es lo mismo: en un aparato que todavía
    // no entró en ninguna (o que ES la bóveda) no hay nada que decir, pero en uno que
    // GUARDA un acta ajena significa que perdió la conexión — y eso hay que contarlo, no
    // tragárselo. Lo de antes lo callaba en los dos casos.
    const m = e?.message || String(e)
    const unpaired = /not paired with a vault/i.test(m)
    notLinked.value = unpaired
    syncError.value = unpaired ? '' : m
    // NO ES UN FALLO no estar emparejado: es el estado normal de un aparato que manda en su
    // propia cuenta. Ni se avisa ni se reintenta —reintentar lo que no depende de la red es
    // dar vueltas para siempre—; si además guarda un acta ajena, eso ya se dice en pantalla
    // (`copiaVieja`) y la salida es conectarlo, no insistir.
    if (unpaired) { failures = 0; clearTimeout(retryTimer) } else {
      // Lo que sí es un fallo, en la consola del navegador: no había ni una línea, así que
      // desde fuera era indistinguible de una pantalla que se cargó bien.
      console.warn('[vault-console] could not sync with the vault:', m)
      failures++
      scheduleRetry()
    }
  } finally { checking.value = false }
  const [a, m, mi] = await Promise.all([
    id.value.profileActa().catch(() => null),
    id.value.profileMembers().catch(() => ({ members: [] })),
    id.value.myMembership().catch(() => null)
  ])
  record.value = a?.acta || null
  members.value = m.members || []
  computeProfileIdShort()
  mine.value = mi
}

/**
 * LA lista de dispositivos, que es UNA: el acta, con el estado de cada uno pegado.
 *
 * Antes había dos —los miembros del acta arriba y los certificados abajo— y no coincidían:
 * quitar desde abajo retiraba los papeles pero dejaba al miembro dentro, así que el aparato
 * seguía apareciendo arriba para siempre. Eso es el «dispositivo fantasma»: la fila de
 * abajo desaparecía, la de arriba no.
 */
const devices = computed(() => members.value.map((m) => {
  const cert = certBySub.value.get(m.pub) || null
  return {
    ...m,
    exp: cert?.exp || null,
    // Un servicio y el master no tienen (ni necesitan) certificado emitido por la bóveda:
    // el master ES quien los firma. Marcar «sin acceso» ahí sería una alarma falsa.
    noAccess: !cert && !m.isMaster && !m.cn && !!certBySub.value.size
  }
}))

/** ¿Puede esta pantalla quitar a ese miembro? El master siempre; un admin, a distancia. */
const canRemove = (m) => !m.isMaster && (isMaster.value || canAdmin.value)

const shortDate = (ms) => {
  try { return new Date(ms).toLocaleDateString(props.lang === 'en' ? 'en-US' : 'es-ES', { day: 'numeric', month: 'long' }) }
  catch (_) { return '' }
}

/**
 * ESTE dispositivo salió del perfil. Lo dispara el aviso FIRMADO por la maestra (phase
 * 'revoked', que además borra el enlace y el acta) o el haberse quitado uno mismo desde
 * aquí. Sin esto la pantalla seguía enseñando el perfil, los miembros y los permisos de una
 * cuenta que ya no existía en este aparato, hasta que a alguien se le ocurriera recargar.
 */
const expelled = ref(false)
/**
 * La CUENTA de este aparato se borró al ser expulsado. Lo hace el pilar de identidad y lo
 * avisa; aquí solo se cuenta, porque si no el aparato se queda mirando una pantalla que no
 * dice qué pasó con su cuenta. Con cuál sigue lo decide el arranque al recargar.
 */
const accountGone = ref(null) // { error?:string }
/** La bóveda nos rechaza pero sin aviso firmado: se avisa, no se borra (wipe-DoS). */
const rejected = ref('')
/**
 * COPIAR el enlace de la invitación. `navigator.clipboard` no existe fuera de un sitio
 * seguro (y en algún navegador viejo tampoco), así que hay respaldo: se selecciona el
 * texto y se copia a la vieja usanza. Si ni eso, el enlace sigue a la vista para copiarlo
 * a mano — que es lo único que hacía falta y no había.
 */
const copied = ref('')
async function copyInvite (url, key) {
  if (!url) return
  try {
    await navigator.clipboard.writeText(url)
  } catch (_) {
    try {
      const ta = document.createElement('textarea')
      ta.value = url; ta.style.position = 'fixed'; ta.style.opacity = '0'
      document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove()
    } catch (__) { return }
  }
  copied.value = key
  setTimeout(() => { if (copied.value === key) copied.value = '' }, 2000)
}

/**
 * Cambiar de cuenta NO es reactivo (por diseño: las pestañas abiertas conservan la suya),
 * así que estrenar la que quedó puesta pasa por recargar. Se ofrece el botón en vez de
 * recargar solo: recargar debajo de los pies a alguien al que acaban de echar es justo lo
 * que hace que no se entienda qué pasó.
 */
const reloadNow = () => { location.href = '/devices' + location.search }

/** Volver a emparejar conserva la query (`?vault=` apunta al iframe con el que corre). */
const pairHref = computed(() => '/d' + location.search)

onMounted(async () => {
  // `markRaw`: la identidad NO puede volverse reactiva. Vue envuelve en un Proxy lo
  // que metes en un ref, y esta instancia habla con su iframe por `postMessage`, que
  // no sabe clonar un Proxy: emparejar moría con «#<Object> could not be cloned».
  // (Venía roto desde que existe esta consola; lo destapó una prueba de punta a punta.)
  try { id.value = markRaw(await Identity.connect(identityOptions())) } catch { fatal.value = t.value.err_connect; loading.value = false; return }
  await refresh()
  loading.value = false
  // El QR de `dotrino-vault pair` abre esta página con el código en el #fragment
  // (que nunca llega al servidor). Si viene, arrancamos la conexión sola.
  // La invitación se queda en la barra MIENTRAS dura el emparejamiento; se limpia al
  // terminar (`connect`). Antes se borraba aquí mismo, nada más entrar, y eso hacía
  // que cualquier recarga durante el proceso cayera en la lista de dispositivos con
  // la invitación ya perdida — «de la nada me sacó a /devices». Y recargas hay: el
  // service worker está en `autoUpdate`, así que cuando se despliega una versión
  // nueva toma el control y RECARGA la página sola, justo encima del código de seis
  // dígitos. Conservando el #fragment la recarga es recuperable: al volver se
  // reanuncia y sale un código nuevo.
  const payload = pairOnly.value ? extractPayload(location.hash) : null
  if (payload) announce(payload)
  offVault = id.value.onVault?.((e) => {
    if (e?.phase === 'acta' || e?.phase === 'renounced') refresh()
    // Nos echaron, y va FIRMADO por la maestra: el enlace y el acta ya se borraron solos.
    // La pantalla tiene que decirlo, no seguir pintando la cuenta que acaba de irse.
    else if (e?.phase === 'revoked') { expelled.value = true; confirming.value = null }
    else if (e?.phase === 'account-removed') { expelled.value = true; accountGone.value = { error: e.error || '' } }
    else if (e?.phase === 'rejected') rejected.value = e.reason || '1'
  })
  await refreshSelf()
  await refreshAdmin()
})

let offVault = null
onBeforeUnmount(() => { try { offVault?.() } catch (_) {} })

// ---------- acciones del master ----------

const confirming = ref(null) // { kind, pub }

/**
 * La contraseña del perfil, SOLO en memoria y solo mientras la pestaña esté abierta.
 * Hace falta para escribir variables privadas: la bóveda la usa para abrir la copia
 * maestra y sellar cada valor a su destinatario. No se guarda en ningún sitio.
 */


async function run (key, fn) {
  busy.value = key; msg.value = null
  try { await fn(); await refresh() }
  catch (e) { msg.value = { kind: 'bad', text: e?.message || String(e) } }
  finally { busy.value = ''; confirming.value = null }
}

const toggleCap = (m, cap) => run('caps-' + m.pub, () => {
  const caps = m.caps.includes(cap) ? m.caps.filter((c) => c !== cap) : [...m.caps, cap]
  return id.value.setCaps(m.pub, caps)
})
/**
 * QUITAR UN DISPOSITIVO — una sola operación, se sea el master o se administre a distancia.
 *
 * Va SIEMPRE por la llave del aparato (`pub`/`sub`), nunca por un certificado suelto. Las
 * dos caras van juntas: fuera del acta (deja de ser miembro y de figurar en la lista) y
 * fuera los papeles (ningún certificado suyo vuelve a servir). Retirar solo el papel —que
 * es lo que hacía esta pantalla— dejaba al miembro dentro del acta sin poder entrar: un
 * fantasma que nadie podía quitar desde aquí, y al que la bóveda además NO le mandaba el
 * aviso firmado de expulsión (mientras siga en el acta, un papel retirado significa
 * «renueva», no «estás fuera»), así que el aparato se quedaba enseñando la cuenta para
 * siempre.
 */
const removeMember = (m) => run('rm-' + m.pub, async () => {
  const isSelf = !!m.isMe
  if (isMaster.value) await id.value.removeMember(m.pub)
  else await id.value.vaultAdmin('revoke', { sub: m.pub })
  if (!isSelf) return
  // Me quité a mí mismo: aquí se acabó la cuenta. Se dice ya (la bóveda acaba de sacarnos
  // del acta, eso es un hecho) y se fuerza un contacto para recoger el aviso FIRMADO, que
  // es lo único que puede borrar el enlace y el acta de este aparato.
  expelled.value = true
  try { await id.value.listVaultDevices() } catch (_) {}
})
const handover = (m) => run('ho-' + m.pub, () => id.value.handoverMaster(m.pub))
const renounceSign = () => run('renounce', () => id.value.renounceCaps(['sign']))

// ---------- conectar este dispositivo a una bóveda ----------

const pairing = ref(false)
const pairCode = ref('')
const pasted = ref('')
// Recién emparejado: hay que explicar que el aparato quedó con DOS cuentas.
const justPaired = ref(false)
const pairError = ref('')
const scanHost = ref(null)
const fileInput = ref(null)

/**
 * Conectar un dispositivo se lleva la página entera mientras dura. Antes los seis
 * dígitos eran un recuadro más dentro de la consola completa —acta, lista de
 * dispositivos, permisos, «que este dispositivo sea la bóveda»—: llegabas por el QR
 * y no se entendía ni que estabas en medio de algo ni cuál de todos los botones te
 * tocaba.
 *
 * Y es UNA pantalla, no dos: escanear el QR YA es tu aceptación, así que no se
 * pregunta otra vez con un «Continuar» de por medio. Lo que la bóveda quiere hacer
 * se lee **junto al código de seis dígitos**, en la misma pantalla, mientras
 * esperas. El que decide de verdad es ese código: no se emite ningún certificado
 * hasta que lo tecleas en la bóveda, y ahí sí puedes no hacerlo.
 */
const pairFlow = computed(() => {
  if (justPaired.value) return 'done'
  if (pairError.value) return 'error'
  if (pairCode.value) return 'code'
  if (pairing.value) return 'connecting'
  return null
})
/** Sale del proceso y devuelve la consola completa. */
const closeFlow = () => {
  pairError.value = ''; justPaired.value = false
  // Emparejar termina donde empieza administrar: en `/devices`. `/d` no lista nada.
  // Se conserva la query: `?vault=` apunta al iframe de identidad y perderlo aquí
  // mandaría la página al de producción a mitad de camino.
  if (pairOnly.value) location.href = '/devices' + location.search
}

/**
 * Invitación legible: compacta (`iss`+`token`) o corta (`conn`), siempre con `sn`.
 * La bóveda vigente emite `t` (cita del proxy); las formas `c`/`b`/`j` siguen valiendo.
 */
function validInvite (o) {
  if (!o || !o.sn) return false
  if (o.v && o.v < 2) return false
  return !!((o.iss && o.token) || o.conn)
}

/**
 * Lee la invitación con el parser COMPARTIDO (`lib/src/invite.js`): la marca de
 * formato del payload dice cómo leerlo, sin probar a ver cuál cuela.
 */
function extractPayload (text) {
  const o = parseInvite(text)
  return validInvite(o) ? o : null
}

/**
 * El QR NO empareja de una: primero se anuncia QUÉ quiere hacer la bóveda y QUÉ
 * consecuencias tiene, y el dueño decide (V9 de `vinculacion-de-cuentas.md`: la
 * pregunta la hace el vault, el dispositivo la muestra con sus consecuencias).
 * El modo viaja en el QR (`m`) junto al nombre de la cuenta (`acct`); un código de
 * una bóveda vieja no trae nada de eso y se trata como `join`, que es lo único que
 * esa bóveda sabe hacer.
 */
function announce (qr) {
  if (!validInvite(qr)) { msg.value = { kind: 'bad', text: t.value.pair_bad }; return }
  msg.value = null
  const mode = qr.m === 'adopt' ? 'adopt' : 'join'
  const account = String(qr.acct || '').slice(0, 40)
  // `markRaw` + copia plana al conectar: el QR viaja por `postMessage` al iframe de
  // identidad, y un Proxy reactivo de Vue NO es clonable («could not be cloned») —
  // guardar el objeto en un ref rompía el emparejamiento entero.
  // Escanear el código YA es aceptar: se arranca de una y lo que la bóveda quiere
  // hacer se cuenta en la misma pantalla del código de seis dígitos.
  flowAccount.value = account
  flowMode.value = mode
  connect({ ...qr }, mode)
}

/** La cuenta que la bóveda declaró, para nombrarla en la pantalla del código. */
const flowAccount = ref('')
/** Qué camino se está haciendo: `join` (camino B) o `adopt` (camino A). */
const flowMode = ref('join')

async function connect (qr, mode = 'join') {
  if (!validInvite(qr)) { msg.value = { kind: 'bad', text: t.value.pair_bad }; return }
  pairing.value = true; pairCode.value = ''; pairError.value = ''; msg.value = null
  const off = id.value.onVault((e) => { if (e?.phase === 'challenge') pairCode.value = e.code })
  try {
    // Cuál de los dos caminos (`vinculacion-de-cuentas.md`), según lo que declaró la bóveda:
    //   · `adopt` (camino A) → la cuenta que YA vive en este aparato pasa a vivir en la
    //     bóveda. Sigue siendo la misma cuenta; lo que cambia es quién manda.
    //   · `join`  (camino B) → la cuenta de la bóveda se materializa aquí como una cuenta
    //     MÁS, con llave nueva. La que estabas usando NO se toca — antes se sobrescribía
    //     sin preguntar, que era la fusión de cuentas que el modelo prohíbe.
    await id.value.enrollDevice(qr, { join: mode === 'adopt' ? 'adopt' : 'new' })
    // Emparejar deja DOS cuentas en el aparato, y eso hay que decirlo: si no, el
    // conmutador aparece con una entrada de más y nadie sabe de dónde salió.
    justPaired.value = true
    await refresh()
  } catch (e) {
    // El error se queda DENTRO del proceso: si se soltara a la consola entera, el
    // dueño acabaría en una pantalla llena de botones sin saber qué salió mal.
    pairError.value = t.value.pair_fail + (e?.message || e)
  } finally {
    off?.(); pairing.value = false; pairCode.value = ''
    // La invitación ya se usó (o se agotó el intento): fuera de la barra, para que
    // volver a abrir la página no dispare otro emparejamiento con un código muerto.
    // `pathname + search`: quitar solo el #fragment. Con `pathname` a secas se iba
    // también la query, y ahí viaja `?vault=` (el iframe de identidad contra el que
    // corre en local y en las pruebas): la página se quedaba apuntando al de producción.
    if (location.hash) { try { history.replaceState(null, '', location.pathname + location.search) } catch (_) {} }
  }
}

const connectPasted = () => announce(extractPayload(pasted.value))

function decodeImage (file) {
  return new Promise((resolve) => {
    const img = new Image()
    img.onload = () => {
      const c = document.createElement('canvas'); c.width = img.naturalWidth; c.height = img.naturalHeight
      try {
        const ctx = c.getContext('2d'); ctx.drawImage(img, 0, 0)
        const d = ctx.getImageData(0, 0, c.width, c.height)
        resolve(jsQR(d.data, d.width, d.height)?.data || null)
      } catch { resolve(null) }
      URL.revokeObjectURL(img.src)
    }
    img.onerror = () => resolve(null)
    img.src = URL.createObjectURL(file)
  })
}

async function onFile (ev) {
  const f = ev.target.files?.[0]; if (!f) return
  const text = /^image\//.test(f.type) ? await decodeImage(f) : await f.text()
  if (!text) { msg.value = { kind: 'bad', text: t.value.no_qr }; return }
  announce(extractPayload(text))
}

const scanning = ref(false)
let scanStop = null
async function scan () {
  scanning.value = true
  const video = scanHost.value.querySelector('video')
  const c = document.createElement('canvas'); const ctx = c.getContext('2d')
  let stream = null, raf = null, done = false
  const stop = (val) => {
    if (done) return; done = true
    if (raf) cancelAnimationFrame(raf)
    stream?.getTracks().forEach((x) => x.stop())
    scanning.value = false
    if (val) announce(extractPayload(val))
  }
  scanStop = () => stop(null)
  const tick = () => {
    if (done) return
    if (video.readyState >= 2 && video.videoWidth) {
      c.width = video.videoWidth; c.height = video.videoHeight
      ctx.drawImage(video, 0, 0, c.width, c.height)
      try {
        const d = ctx.getImageData(0, 0, c.width, c.height)
        const r = jsQR(d.data, d.width, d.height)
        if (r?.data) return stop(r.data)
      } catch (_) {}
    }
    raf = requestAnimationFrame(tick)
  }
  try {
    stream = await navigator.mediaDevices.getUserMedia({ video: { facingMode: 'environment' } })
    video.srcObject = stream
    await video.play().catch(() => {})
    raf = requestAnimationFrame(tick)
  } catch { scanning.value = false; msg.value = { kind: 'bad', text: t.value.cam_err } }
}

// ---------- este dispositivo como bóveda ----------

const self = ref({ enabled: false, running: false })
const selfQr = ref(null)
/**
 * La MISMA invitación que pinta el QR, en texto.
 *
 * El QR sirve cuando el otro aparato tiene cámara y está delante. Si no —un PC, un
 * teléfono que no enfoca, o alguien que quiere mandársela a otra pantalla suya— no había
 * nada que hacer: la dirección existía y no se enseñaba. Es la misma cadena que codifica
 * el QR, así que las dos formas llevan exactamente al mismo sitio.
 */
const selfUrl = ref('')
const selfPending = ref([])
const selfCode = ref('')
let selfTimer = null

async function refreshSelf () {
  try {
    self.value = await id.value.selfVaultStatus()
    selfPending.value = self.value.running ? await id.value.selfVaultPending() : []
  } catch (_) {}
}
const selfToggle = () => run('self', async () => {
  await id.value.setSelfVault(!self.value.enabled)
  await refreshSelf()
  await refreshAdmin()
})
const selfPair = () => run('selfpair', async () => {
  const r = await id.value.selfVaultPairing({})
  // El QR lleva el ENLACE compacto, no el JSON: así el otro aparato lo escanea con
  // la cámara y se le abre esta misma consola, en vez de quedarse con un texto que
  // hay que pegar a mano. Y de paso cabe: el JSON daba un QR de 69 módulos.
  selfUrl.value = r?.qr ? inviteUrl(r.qr) : ''
  selfQr.value = selfUrl.value ? qrSvg(selfUrl.value) : null
  clearInterval(selfTimer)
  selfTimer = setInterval(refreshSelf, 2000)
})
const selfApprove = (deviceId) => run('sa-' + deviceId, async () => {
  await id.value.selfVaultApprove(deviceId, selfCode.value.trim())
  selfCode.value = ''; selfQr.value = null; selfUrl.value = ''; clearInterval(selfTimer); await refreshSelf()
})
const selfReject = (deviceId) => run('sr-' + deviceId, async () => {
  await id.value.selfVaultReject(deviceId); await refreshSelf()
})
// ---------- administrar la bóveda REMOTA desde aquí (consola remota) ----------
// docs/consola-remota.md. Lo que se puede hacer sale del cert de este aparato, no de
// esta pantalla: la bóveda vuelve a comprobarlo en cada petición.

const canAdmin = ref(false)      // ¿mi cert lleva `vault:admin`?
const admPending = ref([])       // los que esperan aprobación
const admQr = ref(null)
const admUrl = ref('')
const admCode = ref('')
let admTimer = null

/**
 * Esta sección NO lista dispositivos: la lista es una sola y está arriba (`devices`). Aquí
 * solo queda lo que de verdad es administrar a distancia: dejar entrar a alguien nuevo.
 * Quitar se hace en la fila del aparato, junto a su nombre y su estado, que es donde se ve
 * a quién estás quitando.
 */
async function refreshAdmin () {
  try {
    // PUNTO MUERTO que esto arregla: preguntar primero por el cert dejaba la consola
    // escondida para siempre. `canAdminVault` mira el acta que hay GUARDADA aquí, y la
    // única cosa que trae el acta de la bóveda es `listVaultDevices`… que estaba detrás
    // del `if`. Así que un permiso concedido en la bóveda no llegaba nunca: el acta no se
    // refrescaba porque no se administraba, y no se administraba porque el acta no se
    // refrescaba. Primero se sincroniza (`refresh`), y luego se decide.
    canAdmin.value = await id.value.canAdminVault()
    if (!canAdmin.value) return
    const p = await id.value.vaultAdmin('pending').catch(() => ({ pending: [] }))
    admPending.value = p.pending || []
    // Una vez, al entrar: `refreshAdmin` también corre cada 2 s mientras hay un
    // emparejamiento abierto, y no hay por qué bajar la configuración entera en cada vuelta.
    if (!vars.value) await loadVars().catch((e) => { vars.value = null; varsError.value = e?.message || String(e) })
  } catch (_) { canAdmin.value = false }
}

// ---------- VARIABLES DE ENTORNO (docs/consola-remota.md) ----------
// Lo que se puede ver de una variable lo decide su dueño en la bóveda: de una PÚBLICA
// llega el valor, de una PRIVADA solo el nombre. Poner un valor nuevo se puede en las dos
// —rotar una llave que no puedes leer es justo para lo que sirve—, y borrar no existe.
// Todo viaja dentro de un sobre cifrado con la clave de contenido del perfil: el proxy
// transporta y no ve nada, ni siquiera los nombres.

const vars = ref(null)                       // { ns: {<scope>: [...]}, dev: [...] }
// Por qué no se pudo traer la lista. Estuvo tragándose el error («catch(() => null)») y el
// resultado fue una pantalla que se quedaba en «cargando…» para siempre sin decir nada:
// hizo falta abrir la consola del navegador para enterarse de que fallaba.
const varsError = ref('')
const newGroup = ref('')                   // el nombre que se está tecleando abajo
const newGroups = ref([])                 // grupos creados aquí y todavía sin ninguna variable

/** Destino de una variable: `ns:<scope>` o `dev:<pubkey>`. */
const targetOf = (t) => (t.startsWith('dev:') ? { pub: t.slice(4) } : { ns: t.slice(3) })

async function loadVars () {
  varsError.value = ''
  const r = await id.value.vaultAdmin('vars')
  vars.value = JSON.parse(await id.value.openContent(r.enc))
}

/**
 * Los grupos: los que ya tienen variables y los que acabas de crear aquí. Un grupo VACÍO no
 * existe en la bóveda (un cajón sin nada se borra solo), así que el recién creado vive en
 * esta pantalla hasta que le pongas la primera variable. Es lo que permite el orden que se
 * espera: primero el grupo, y dentro las variables.
 */
const scopeNames = computed(() => {
  const del = Object.keys(vars.value?.ns || {})
  return [...new Set([...del, ...newGroups.value])].sort()
})

/**
 * La DEUDA de un aparato: qué variables no puede abrir (§8.11). Sale de la bóveda ya
 * calculada — es ella la que sabe qué envoltura tiene cada uno—, y se junta todo en una
 * lista de nombres porque a quien administra le da igual de qué cajón salga: lo que
 * necesita saber es que ese aparato NO está funcionando del todo.
 */
const debtOf = (pub) => {
  const d = (vars.value?.incomplete || []).find((x) => x.pub === pub)
  if (!d) return null
  const keys = [...new Set(Object.values(d.owners || {}).flat())]
  return keys.length ? { keys } : null
}

/** Las variables de un aparato, para pintarlas en SU fila. */
const varsOfDevice = (pub) => (vars.value?.dev || []).find((d) => d.pub === pub)?.keys || []
/**
 * Cajones de variables de aparatos que ya no están en el acta. No caben en ninguna fila, y
 * esconderlos sería dejar configuración invisible: se listan aparte, marcados.
 */
/**
 * Los cajones que quedaron a deber un sellado. No es un detalle de estado: mientras
 * esté ahí, esos aparatos NO leen su configuración, y quien administra desde aquí es
 * justo quien puede saldarlo — tiene la contraseña, la bóveda no.
 */
const pendingVars = computed(() => Object.entries(vars.value?.pending || {})
  .map(([owner, info]) => ({ owner, kind: info?.kind || 'rewrap' })))

/** La bóveda dice si su perfil tiene contraseña. Sin ella, el sellado no protege de
    una copia del disco, y eso se dice — no se calla por incómodo. */
const noPassword = computed(() => vars.value ? vars.value.hasPassword === false : false)

const orphanVars = computed(() => (vars.value?.dev || [])
  .filter((d) => !members.value.some((m) => m.pub === d.pub)))

/**
 * Guarda TODO lo editado de un destino en UNA sola operación. Es lo que `Vars.vue` llama
 * desde su único botón.
 *
 * Que sea una sola no es una comodidad de la pantalla: cada guardado hace que la bóveda
 * avise a la aplicación de que su configuración cambió, y esa aplicación se reinicia para
 * leerla entera y fresca. Guardando de una en una, seis variables eran seis reinicios, y
 * los cinco primeros arrancaban la aplicación con la configuración a medio poner.
 *
 * Los nombres viajan DENTRO del sobre cifrado, igual que los valores: el proxy transporta
 * y no aprende ni cómo se llaman las variables de tus servicios.
 */
function saveVars ({ target, items }) {
  return run('var-' + target, async () => {
    // GUARDAR NO PIDE LA CONTRASEÑA, y ese es el cambio entero: sellar solo necesita las
    // llaves PÚBLICAS de quien va a leer, así que la bóveda puede hacerlo sin ningún
    // secreto (`docs/secretos-sellados.md` §8.1). Antes había que teclear aquí la frase
    // del perfil —la que abre TODOS los cajones— y eso es justo lo que no debe pasar en
    // un navegador. Los valores siguen viajando dentro del sobre cifrado.
    const enc = await id.value.sealContent(JSON.stringify({ items }))
    await id.value.vaultAdmin('var.setMany', { ...targetOf(target), enc })
    await loadVars()
  })
}

/**
 * VER el valor de una variable. La bóveda entrega el sobre y **la envoltura dirigida a
 * este aparato**; abrirlo lo hace el navegador con su propia llave de cifrado, que no
 * sale de aquí (§8.2). Ninguna contraseña de por medio, en ningún momento.
 */
async function revealVar (target, key, ts = null) {
  const r = await id.value.vaultAdmin('var.reveal', { ...targetOf(target), key, ...(ts ? { ts } : {}) })
  if (r?.pub) return r.v                       // una pública no está cerrada
  return id.value.openSealedValue(r.wrap, r.e)
}

/** Las versiones anteriores de una variable (sin valores: son sobres). */
async function historyVar (target, key) {
  const r = await id.value.vaultAdmin('var.history', { ...targetOf(target), key })
  return r?.items || []
}

/**
 * VOLVER A UNA VERSIÓN ANTERIOR: se abre aquí y se vuelve a guardar. No es un modo
 * especial de nada — es ver + escribir—, así que hereda las dos reglas: abrir lo hace
 * este aparato con su llave, y escribir no pide nada.
 */
async function restoreVar (target, key, ts) {
  const value = await revealVar(target, key, ts)
  await saveVars({ target, items: [{ key, value, public: false }] })
}

/** Crear un grupo es solo abrirle su apartado: existe de verdad con la primera variable. */
function createGroup () {
  const ns = newGroup.value.trim().toLowerCase()
  if (!ns) return
  if (!newGroups.value.includes(ns)) newGroups.value = [...newGroups.value, ns]
  newGroup.value = ''
}

const admPair = () => run('admpair', async () => {
  const r = await id.value.vaultAdmin('pair')
  admUrl.value = r?.qr ? inviteUrl(r.qr) : ''
  admQr.value = admUrl.value ? qrSvg(admUrl.value) : null
  clearInterval(admTimer)
  admTimer = setInterval(refreshAdmin, 2000)
})
const admApprove = (deviceId) => run('aa-' + deviceId, async () => {
  await id.value.vaultAdmin('approve', { deviceId, code: admCode.value.trim() })
  admCode.value = ''; admQr.value = null; admUrl.value = ''; clearInterval(admTimer); await refreshAdmin()
})
const admReject = (deviceId) => run('ar-' + deviceId, async () => {
  await id.value.vaultAdmin('reject', { deviceId }); await refreshAdmin()
})

onBeforeUnmount(() => { clearInterval(selfTimer); clearInterval(admTimer) })
</script>

<template>
  <section class="console">
    <!-- SIN título ni presentación, tampoco durante el emparejamiento. Una pantalla es
         administrativa o informativa, no las dos: aquí se opera, y lo que hay que hacer
         lo dice cada paso. El qué-es-esto vive en el home. -->

    <p v-if="loading" class="muted">{{ t.loading }}</p>
    <div v-else-if="fatal" class="banner bad">{{ fatal }}</div>

    <!-- ═══ Este dispositivo salió del perfil ═══
         Se lleva la pantalla entera, como el emparejamiento: seguir pintando la lista de
         miembros y los botones de una cuenta que aquí ya no existe era lo que hacía que
         quitarse a uno mismo pareciera no haber hecho nada. -->
    <div v-else-if="expelled" class="flow" data-testid="expelled">
      <div class="card bad">
        <strong>{{ t.gone_t }}</strong>
        <p>{{ t.gone_b }}</p>
        <p v-if="accountGone && !accountGone.error" data-testid="expelled-account">{{ t.gone_reload }}</p>
        <p v-else-if="accountGone" class="muted" data-testid="expelled-stuck">
          {{ t.gone_stuck }} <code class="mid">{{ accountGone.error }}</code>
        </p>
        <div class="row">
          <button v-if="accountGone && !accountGone.error" class="btn" data-testid="expelled-reload"
                  @click="reloadNow">{{ t.gone_reload_go }}</button>
          <a class="btn ghost" data-testid="expelled-pair" :href="pairHref">{{ t.gone_go }}</a>
        </div>
      </div>
    </div>

    <!-- ═══ Conectando este dispositivo: la página es SOLO esto mientras dura ═══
         Tres pasos, uno visible a la vez. Nada de acta, ni lista de dispositivos,
         ni permisos, ni «que este dispositivo sea la bóveda»: eso vuelve al
         terminar. Llegar por un QR y encontrarte la consola entera era no
         entender ni que estabas en medio de algo ni qué botón te tocaba. -->
    <div v-else-if="pairFlow" class="flow" data-testid="pair-flow">
      <!-- Hablando con la bóveda (dura un segundo) -->
      <div v-if="pairFlow === 'connecting'" class="card" data-testid="pair-connecting">
        <p class="big">{{ t.flow_connecting }}</p>
        <p class="muted">{{ t.flow_connecting_b }}</p>
      </div>

      <!-- LA pantalla del emparejamiento: los seis dígitos y, al lado, qué quiere
           hacer la bóveda. Aquí no hay botones a propósito — lo único que hay que
           hacer está en la bóveda, y no aprobar ahí es la forma de decir que no. -->
      <div v-else-if="pairFlow === 'code'" class="card codebox" data-testid="pair-code">
        <p class="big">{{ t.pair_code_t }}</p>
        <div class="digits">{{ pairCode }}</div>
        <p class="muted">{{ t.pair_code_b }}</p>
        <!-- Si la bóveda es la del PC, la acción es literalmente esta línea. Decirla
             quita toda duda sobre «dónde se aprueba». -->
        <p class="cmd">{{ t.pair_code_cli }} <code>dotrino-vault approve {{ pairCode }}</code></p>
        <p class="waiting">{{ t.flow_waiting }}</p>
        <div class="what" data-testid="announce-what">
          <strong>{{ t.ann_t }}</strong>
          <p>{{ flowMode === 'adopt' ? t.ann_adopt_h(flowAccount) : t.ann_join_h(flowAccount) }}</p>
          <p class="muted">{{ flowMode === 'adopt' ? t.ann_adopt_c : t.ann_join_c }}</p>
        </div>
      </div>

      <!-- Listo, y qué quedó en el aparato -->
      <div v-else-if="pairFlow === 'done'" class="card done" data-testid="two-accounts">
        <strong>{{ flowMode === 'adopt' ? t.adopt_done : t.pair_done }}</strong>
        <p v-if="flowMode === 'adopt'">{{ t.adopt_done_b }}</p>
        <p v-else>{{ t.two_title }}. {{ t.two_body }}</p>
        <details v-if="flowMode !== 'adopt'">
          <summary>{{ t.two_del }}</summary>
          <ol class="muted">
            <li>{{ t.two_del_1 }}</li>
            <li>{{ t.two_del_2 }}</li>
            <li>{{ t.two_del_3 }}</li>
          </ol>
          <a class="btn ghost sm" href="https://profile.dotrino.com/" target="_blank" rel="noopener"
             data-testid="goto-profile">{{ t.two_del_link }}</a>
        </details>
        <div class="row">
          <button class="btn" data-testid="flow-close" @click="closeFlow">{{ t.flow_close }}</button>
        </div>
      </div>

      <!-- No salió -->
      <div v-else-if="pairFlow === 'error'" class="card bad" data-testid="pair-error">
        <strong>{{ t.flow_failed }}</strong>
        <p>{{ pairError }}</p>
        <div class="row">
          <button class="btn ghost" data-testid="flow-back" @click="closeFlow">{{ t.back }}</button>
        </div>
      </div>
    </div>

    <!-- `/d` es SOLO emparejar: aquí abajo empieza lo administrativo, y eso vive en
         `/devices`. Sin invitación en la URL, lo único que se ofrece es la entrada al
         proceso (escanear / abrir / pegar). -->
    <template v-else-if="pairOnly">
      <div v-if="msg" class="banner" :class="msg.kind">{{ msg.text }}</div>
      <h2>{{ t.pair_t }}</h2>
      <p class="muted" data-testid="pair-new-account">{{ t.pair_new_account }}</p>
      <div class="row">
        <button class="btn" data-testid="scan" :disabled="pairing" @click="scan">{{ t.pair_scan }}</button>
        <button class="btn ghost" :disabled="pairing" @click="fileInput.click()">{{ t.pair_file }}</button>
      </div>
      <input ref="fileInput" type="file" accept="image/*,.dpair,.json,text/plain" hidden @change="onFile" />
      <div ref="scanHost" class="scanbox" v-show="scanning">
        <video playsinline muted></video>
        <button class="btn ghost sm" @click="scanStop && scanStop()">{{ t.cancel }}</button>
      </div>
      <details>
        <summary>{{ t.pair_paste }}</summary>
        <textarea v-model="pasted" rows="3" data-testid="pair-paste"
                  placeholder="cAgKy9m6jD310-TFoQuRirKOoh5EUSYOfjGi9BPEe-GX9sZT…"></textarea>
        <button class="btn ghost" data-testid="pair-go" :disabled="pairing" @click="connectPasted">{{ t.pair_go }}</button>
      </details>
    </template>

    <template v-else>
      <div v-if="msg" class="banner" :class="msg.kind">{{ msg.text }}</div>

      <!-- Sin esto, un fallo de sincronía era INVISIBLE: la pantalla enseñaba tan
           tranquila la copia del acta del día que emparejaste, y no había forma de saber
           que llevaba semanas sin hablar con la bóveda. -->
      <div v-if="syncError" class="banner bad" data-testid="sync-error">
        <strong>{{ t.sync_err_t }}</strong> — {{ t.sync_err_b }}
        <code class="mid">{{ syncError }}</code>
      </div>

      <!-- Copia vieja Y sin forma de confirmarla: es lo que hay que decir en la cara, con
           la salida al lado. Callarlo dejaba una pantalla que parecía al día. -->
      <div v-else-if="staleCopy" class="banner warn" data-testid="no-link">
        <strong>{{ t.nolink_t }}</strong> — {{ t.nolink_b }}
        <div class="row">
          <a class="btn ghost sm" data-testid="nolink-pair" :href="pairHref">{{ t.gone_go }}</a>
        </div>
      </div>

      <!-- La bóveda nos rechaza, pero el mensaje NO va firmado: no borra nada (sería un
           wipe-DoS). Lo que sí se puede hacer es contarlo, en vez de callarlo. -->
      <div v-if="rejected" class="banner warn" data-testid="rejected">
        <strong>{{ t.rejected_t }}</strong> — {{ t.rejected_b }}
      </div>

      <div v-if="soloMember" class="banner warn" data-testid="solo-warning">
        <strong>{{ t.solo_warn_t }}</strong> — {{ t.solo_warn_b }}
      </div>

      <!-- Ficha del acta: qué cuenta es, por qué versión va y quién es el Master. Es
           DATO, no explicación, y por eso se queda a la vista. -->
      <ul class="facts" v-if="record">
        <li>{{ t.profile }} <code data-testid="profile-id">{{ profileIdShort || '—' }}</code></li>
        <li>{{ t.version }} <code>#{{ record.seq }}</code></li>
        <li>{{ t.master }} <code>{{ members.find(m => m.isMaster)?.label || members.find(m => m.isMaster)?.id }}</code></li>
        <!-- CUÁNDO se confirmó esto con la bóveda, y con qué volver a intentarlo. Es dato y
             es acción: exactamente lo que va en una pantalla de administración. -->
        <li data-testid="sync-state" class="muted">
          {{ checking ? t.sync_checking : (checkedAt ? t.sync_at(shortTime(checkedAt)) : t.sync_stale) }}
        </li>
      </ul>

      <!-- LOS DISPOSITIVOS — una sola lista, la del acta, con el estado de cada uno.
           Lo que se pueda hacer con cada fila sale de lo que puede ESTE aparato: el
           master lo puede todo; uno con «administra» puede conectar y quitar. -->
      <h2>{{ t.members }}</h2>
      <ul class="members" data-testid="members">
        <li v-for="m in devices" :key="m.pub" class="member" :data-member="m.id">
          <div class="who">
            <strong>{{ m.label || m.id }}</strong>
            <span class="tag" v-if="m.isMe">{{ t.me }}</span>
            <span class="tag master" v-if="m.isMaster">{{ t.is_master }}</span>
            <span class="tag svc" v-if="m.cn">{{ t.service }} «{{ m.cn }}»</span>
            <!-- Está en el acta pero no puede entrar. Es un AVISO, no una explicación:
                 sin él, la fila parece un aparato normal y nadie la quita nunca. -->
            <span class="tag out" v-if="m.noAccess" :data-testid="'noaccess-' + m.id">{{ t.dev_nocert }}</span>
            <span class="tag" v-else-if="m.exp">{{ t.dev_until(shortDate(m.exp)) }}</span>
            <code class="mid">{{ m.id }}</code>
          </div>
          <p v-if="m.noAccess" class="muted svc-note">{{ t.dev_nocert_b }}</p>
          <div class="caps">
            <button v-for="c in (m.cn ? ['secrets'] : ['sign','store','read','admin'])" :key="c"
                    class="cap" :class="{ on: m.caps.includes(c) }"
                    :disabled="!isMaster || busy === 'caps-' + m.pub"
                    :data-testid="'cap-' + c + '-' + m.id"
                    @click="toggleCap(m, c)">{{ t.caps[c] }}</button>
            <span v-if="!m.caps.length" class="muted">{{ t.caps_none }}</span>
          </div>
          <p v-if="m.cn" class="muted svc-note">{{ t.service_note }}</p>
          <!-- APARATO EN DEUDA: está en el acta pero no puede abrir lo suyo. Pasa siempre
               que entra uno nuevo — envolverle su llave exige abrir la de contenido, y eso
               pide la frase. Se dice AQUÍ, en su fila, porque es una propiedad del aparato
               y no del cajón; y se dice qué hacer, que si no es solo un susto. -->
          <p v-if="debtOf(m.pub)" class="warn debt" :data-testid="'debt-' + m.id">
            {{ t.debt_t }} <code>{{ debtOf(m.pub).keys.join(', ') }}</code> — {{ t.debt_b }}
          </p>
          <!-- LAS VARIABLES DE UN SERVICIO, EN SU FILA. Son suyas —solo él las lee— así que
               se administran donde se le ve: nombre, permisos y configuración juntos. Antes
               había que bajar a otra sección y elegirlo en un desplegable «¿Dónde?».

               EN LOS DEMÁS APARATOS NO SALE NADA, ni el título ni una explicación de por qué:
               un teléfono no lee variables (`requireService`), así que un apartado vacío en su
               fila solo sería ruido repetido en toda la lista. Lo que un aparato así arrastre
               de antes se sigue viendo y se puede cambiar — configuración invisible es
               configuración que nadie arregla el día que falla. -->
          <div v-if="canAdmin && vars && (m.cn || varsOfDevice(m.pub).length)" class="devvars"
               :data-testid="'devvars-' + m.id">
            <h3>{{ t.var_dev_t }}</h3>
            <Vars :target="'dev:' + m.pub" :tid="m.id" :rows="varsOfDevice(m.pub)"
                  :t="t" :busy="busy" :save="saveVars" :add="!!m.cn"
                  :reveal="(k) => revealVar('dev:' + m.pub, k)"
                  :history="(k) => historyVar('dev:' + m.pub, k)"
                  :restore="(k, ts) => restoreVar('dev:' + m.pub, k, ts)" />
          </div>
          <div class="acts">
            <button v-if="m.isMe && m.caps.includes('sign')" class="btn ghost sm"
                    data-testid="renounce" @click="confirming = { kind: 'renounce', pub: m.pub }">{{ t.act_renounce }}</button>
            <button v-if="isMaster && !m.isMaster" class="btn ghost sm" :data-testid="'handover-' + m.id"
                    @click="confirming = { kind: 'handover', pub: m.pub }">{{ t.act_handover }}</button>
            <!-- Quitar vive AQUÍ, en la fila del aparato, y en ningún otro sitio: es donde
                 se ve a quién se está quitando. El botón suelto de la sección de abajo
                 quitaba «C8AA-7DCF» sin decir que ese eras tú, y sin preguntar. -->
            <button v-if="canRemove(m)" class="btn danger sm" :data-testid="'remove-' + m.id"
                    @click="confirming = { kind: 'remove', pub: m.pub }">{{ t.act_remove }}</button>
          </div>
          <div v-if="confirming && confirming.pub === m.pub" class="confirm">
            <span>{{ confirming.kind === 'remove' ? (m.isMe ? t.confirm_remove_me : t.confirm_remove) : confirming.kind === 'handover' ? t.confirm_handover : t.confirm_renounce }}</span>
            <button class="btn danger sm" data-testid="confirm-yes" :disabled="!!busy"
                    @click="confirming.kind === 'remove' ? removeMember(m) : confirming.kind === 'handover' ? handover(m) : renounceSign()">{{ t.yes }}</button>
            <button class="btn ghost sm" @click="confirming = null">{{ t.cancel }}</button>
          </div>
        </li>
      </ul>

      <!-- Conectar este dispositivo a una bóveda. Aquí solo está la ENTRADA al
           proceso (escanear / abrir archivo / pegar); en cuanto hay una invitación,
           la pantalla del proceso se lo lleva todo (ver `pairFlow`). -->
      <template v-if="!alreadyInVault">
      <h2>
        {{ t.pair_t }}
        <button type="button" class="i" data-testid="info-pair" :aria-expanded="info === 'pair'"
                :aria-label="t.info_label" @click="toggleInfo('pair')">i</button>
      </h2>
      <p v-if="info === 'pair'" class="muted info-panel">{{ t.pair_b }}</p>
      <p class="muted" data-testid="pair-new-account">{{ t.pair_new_account }}</p>
      <div class="row">
        <button class="btn" data-testid="scan" :disabled="pairing" @click="scan">{{ t.pair_scan }}</button>
        <button class="btn ghost" :disabled="pairing" @click="fileInput.click()">{{ t.pair_file }}</button>
      </div>
      <input ref="fileInput" type="file" accept="image/*,.dpair,.json,text/plain" hidden @change="onFile" />
      <div ref="scanHost" class="scanbox" v-show="scanning">
        <video playsinline muted></video>
        <button class="btn ghost sm" @click="scanStop && scanStop()">{{ t.cancel }}</button>
      </div>
      <details>
        <summary>{{ t.pair_paste }}</summary>
        <textarea v-model="pasted" rows="3" data-testid="pair-paste"
                  placeholder="cAgKy9m6jD310-TFoQuRirKOoh5EUSYOfjGi9BPEe-GX9sZT…"></textarea>
        <button class="btn ghost" data-testid="pair-go" :disabled="pairing" @click="connectPasted">{{ t.pair_go }}</button>
      </details>

      <!-- Este dispositivo como bóveda -->
      <h2>
        {{ t.self_t }}
        <button type="button" class="i" data-testid="info-self" :aria-expanded="info === 'self'"
                :aria-label="t.info_label" @click="toggleInfo('self')">i</button>
      </h2>
      <p v-if="info === 'self'" class="muted info-panel">{{ t.self_b }}</p>
      <div class="row">
        <span class="tag" :class="{ master: self.running }">{{ self.running ? t.self_on : t.self_off }}</span>
        <button class="btn ghost" data-testid="self-toggle" @click="selfToggle">{{ self.enabled ? t.self_stop : t.self_start }}</button>
        <button v-if="self.running" class="btn" data-testid="self-pair" @click="selfPair">{{ t.self_pair }}</button>
      </div>
      <div v-if="selfQr" class="qrbox" v-html="selfQr"></div>
      <div v-if="selfUrl" class="invite" data-testid="self-invite">
        <span class="muted">{{ t.invite_url }}</span>
        <code class="url">{{ selfUrl }}</code>
        <button class="btn ghost sm" data-testid="self-copy" @click="copyInvite(selfUrl, 'self')">
          {{ copied === 'self' ? t.invite_copied : t.invite_copy }}
        </button>
      </div>
      </template>
      <div v-for="p in selfPending" :key="p.deviceId" class="pending" data-testid="self-pending">
        <span>{{ t.self_pending }}: <code>{{ p.deviceId }}</code></span>
        <input v-model="selfCode" :placeholder="t.self_code_ph" inputmode="numeric" data-testid="self-code" />
        <button class="btn sm" data-testid="self-approve" @click="selfApprove(p.deviceId)">{{ t.self_approve }}</button>
        <button class="btn ghost sm" @click="selfReject(p.deviceId)">{{ t.self_reject }}</button>
      </div>

      <!-- Administrar la bóveda desde aquí: solo si el cert de este aparato lo permite -->
      <template v-if="canAdmin">
        <h2>
          {{ t.adm_t }}
          <button type="button" class="i" data-testid="info-adm" :aria-expanded="info === 'adm'"
                  :aria-label="t.info_label" @click="toggleInfo('adm')">i</button>
        </h2>
        <p v-if="info === 'adm'" class="muted info-panel">{{ t.adm_b }}</p>
        <div class="row">
          <button class="btn" data-testid="adm-pair" @click="admPair">{{ t.adm_pair }}</button>
        </div>
        <div v-if="admQr" class="qrbox" v-html="admQr"></div>
        <div v-if="admUrl" class="invite" data-testid="adm-invite">
          <span class="muted">{{ t.invite_url }}</span>
          <code class="url">{{ admUrl }}</code>
          <button class="btn ghost sm" data-testid="adm-copy" @click="copyInvite(admUrl, 'adm')">
            {{ copied === 'adm' ? t.invite_copied : t.invite_copy }}
          </button>
        </div>
        <div v-for="p in admPending" :key="p.deviceId" class="pending" data-testid="adm-pending">
          <span>{{ t.adm_pending }}: <code>{{ p.deviceId }}</code></span>
          <input v-model="admCode" :placeholder="t.adm_code_ph" inputmode="numeric" data-testid="adm-code" />
          <button class="btn sm" data-testid="adm-approve" @click="admApprove(p.deviceId)">{{ t.adm_approve }}</button>
          <button class="btn ghost sm" data-testid="adm-reject" @click="admReject(p.deviceId)">{{ t.adm_reject }}</button>
        </div>
        <p v-if="admPending.length" class="muted warn">{{ t.adm_warn }}</p>

        <!-- VARIABLES DE ENTORNO. Pantalla administrativa: lo que se ve son las variables
             y los botones. El qué-es-esto (qué significa pública) vive detrás de la (i);
             lo que NO se esconde es la marca de cada una, que es un dato operativo. -->
        <h2>
          {{ t.var_t }}
          <button type="button" class="i" data-testid="info-vars" :aria-expanded="info === 'vars'"
                  :aria-label="t.info_label" @click="toggleInfo('vars')">i</button>
        </h2>
        <p v-if="info === 'vars'" class="muted info-panel">{{ t.var_b }}</p>

        <!-- Puntero, no explicación: aquí abajo SOLO están los grupos, y quien busque las
             de un aparato tiene que saber que están arriba (lo mismo que hace la TUI). -->
        <p class="muted devhint" data-testid="var-dev-hint">{{ t.var_dev_hint }}</p>
        <p v-if="!vars && !varsError" class="muted" data-testid="vars-loading">{{ t.loading }}</p>
        <p v-if="varsError" class="muted warn" data-testid="vars-error">{{ varsError }}</p>
        <template v-else>
          <!-- SOLO LOS GRUPOS: las de un servicio se administran en su fila, arriba. Cada
               grupo lleva dentro sus variables y su formulario; el grupo se crea primero,
               abajo, y las variables se ponen dentro de su apartado. -->
          <!-- La contraseña aparece SOLO cuando la bóveda la pide, y una vez para toda
               la pantalla: es del perfil, no de cada variable. -->
          <div v-if="noPassword" class="pendbar" data-testid="vars-nopassword">
            <strong>{{ t.nopwd_t }}</strong>
            <small>{{ t.nopwd_b }}</small>
          </div>

          <div v-if="pendingVars.length" class="pendbar" data-testid="vars-pending">
            <strong>{{ t.pend_t }}</strong>
            <ul>
              <li v-for="p in pendingVars" :key="p.owner" :data-owner="p.owner">
                <code>{{ p.owner }}</code> — {{ p.kind === 'rotate' ? t.pend_rotate : t.pend_rewrap }}
              </li>
            </ul>
            <small>{{ t.pend_b }}</small>
          </div>

          <ul class="vars" data-testid="vars">
            <li v-for="ns in scopeNames" :key="ns" class="vargroup" :data-scope="ns">
              <div class="who"><strong>{{ ns }}</strong><span class="tag">{{ t.var_shared }}</span></div>
              <Vars :target="'ns:' + ns" :tid="ns" :rows="vars.ns[ns] || []"
                    :t="t" :busy="busy" :save="saveVars"
                    :reveal="(k) => revealVar('ns:' + ns, k)"
                    :history="(k) => historyVar('ns:' + ns, k)"
                    :restore="(k, ts) => restoreVar('ns:' + ns, k, ts)" />
            </li>

            <!-- Cajones de aparatos que ya no están en el acta: no tienen fila arriba. -->
            <li v-for="d in orphanVars" :key="d.pub" class="vargroup" :data-device="d.id">
              <div class="who">
                <strong>{{ d.label || d.id }}</strong>
                <span class="tag svc" v-if="d.cn">{{ t.service }} «{{ d.cn }}»</span>
                <code class="mid">{{ d.id }}</code>
                <span class="tag out">{{ t.var_orphan }}</span>
              </div>
              <div v-for="v in d.keys" :key="v.key" class="varrow" :data-var="d.id + '/' + v.key">
                <code>{{ v.key }}</code>
                <span v-if="v.public" class="val" :data-testid="'val-' + v.key">{{ v.value }}</span>
                <span v-else class="tag out">{{ t.var_private }}</span>
              </div>
            </li>
          </ul>

          <div class="varnew" data-testid="var-new-group">
            <input v-model="newGroup" type="text" :placeholder="t.var_scope_ph" data-testid="var-new-ns"
                   @keyup.enter="createGroup" />
            <button class="btn sm" data-testid="var-new-group-save"
                    :disabled="!newGroup.trim()" @click="createGroup">{{ t.var_group_new }}</button>
          </div>
        </template>
      </template>
    </template>
  </section>
</template>

<style scoped>
/* Lo que está sin entregar se dice en rojo y arriba: es lo único de esta pantalla que
   significa «algo tuyo no está funcionando ahora mismo». */
.pendbar { margin: .75rem 0; padding: .6rem .75rem; border-radius: 8px;
  border: 1px solid var(--bad, #c94f4f); background: color-mix(in srgb, var(--bad, #c94f4f) 8%, transparent); }
.pendbar ul { margin: .4rem 0 0; padding-left: 1.1rem; }
.pendbar li { margin: .15rem 0; }
.pendbar code { font-size: .92em; }
.pendbar small { display: block; margin-top: .45rem; opacity: .8; }

/* Botón (i): pequeño, al lado del título, sin robarle protagonismo a lo que se administra. */
.i {
  border: 1px solid currentColor; background: none; color: inherit; opacity: .5;
  border-radius: 50%; width: 1.25em; height: 1.25em; line-height: 1; font-size: .7em;
  font-style: italic; font-weight: 700; cursor: pointer; vertical-align: middle; margin-left: .5em;
  padding: 0;
}
.i:hover, .i[aria-expanded="true"] { opacity: 1; }
.debt { margin: .35rem 0 0; font-size: .9em; }
.debt code { font-size: .95em; }
/* Variables: una fila por variable, el valor a la vista solo si es pública. */
.vars { list-style: none; padding: 0; margin: 0; }
.vargroup { border-top: 1px solid #1e2a3d; padding: 10px 0; }
.varrow { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 6px 0 0 12px; }
.varrow .val { font-family: ui-monospace, monospace; font-size: 13px; word-break: break-all; }
.varnew { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 12px; }
.varnew input { background: #0d1521; color: #dbe7f7; border: 1px solid #223047; border-radius: 8px; padding: 6px 10px; font: inherit; font-size: 13px; }
/* Las variables de un servicio, dentro de su fila: subordinadas a ella, no otra sección. */
.devvars { border-top: 1px solid #1e2a3d; margin: 10px 0 0; padding-top: 10px; }
.devvars h3 { font-size: 13px; font-weight: 600; color: #9fb0c9; margin: 0; }
.devhint { font-size: 13px; margin: 4px 0 0; }
.info-panel { margin-top: .35rem; }
.console { max-width: 860px; margin: 0 auto; padding: 24px 18px 64px; }
h1 { font-size: clamp(24px, 4vw, 34px); margin: 0 0 6px; }
h2 { font-size: 18px; margin: 32px 0 8px; }
.lead { color: #9fb0c9; margin: 0 0 20px; }
.muted { color: #8ea0b8; }
.facts { list-style: none; display: flex; flex-wrap: wrap; gap: 8px 18px; padding: 0; margin: 0 0 8px; color: #9fb0c9; }
.facts code, .mid { background: #131c2b; border-radius: 6px; padding: 1px 6px; font-size: 12px; }
.banner { border-radius: 10px; padding: 10px 12px; margin: 12px 0; font-size: 14px; }
.banner.ok { background: #0f2a1c; color: #7fe0a8; }
.banner.bad { background: #2a1113; color: #ff9aa2; }
/* ── La pantalla del PROCESO de conectar ─────────────────────────────────────
   Una sola tarjeta grande, centrada, con los tres pasos arriba. Nada compite con
   ella: mientras dura el proceso no hay nada más en la página. */
.flow { max-width: 560px; margin: 8px auto 0; }
.card { background: #0f1725; border: 1px solid #24344d; border-radius: 14px; padding: 20px; display: flex; flex-direction: column; gap: 8px; align-items: flex-start; }
.card p { margin: 0; }
.card strong { color: #9cc4ff; font-size: 15px; }
/* Lo que la bóveda va a hacer se lee ANTES de aceptar: en grande, no al vuelo. */
.card .big { font-size: 18px; line-height: 1.35; color: #eaf1fb; }
.card.announce { border-color: #2f4a6d; }
.card.done { border-color: #2c5c44; }
.card.done strong { color: #7fe0a8; }
.card.bad { border-color: #5a2027; }
.card.bad strong { color: #ff9aa2; }
.card details { width: 100%; }
.card ol { padding-left: 20px; display: flex; flex-direction: column; gap: 3px; margin: 0 0 8px; }
.waiting { color: #ffd98a; font-size: 13px; }
/* Qué quiere hacer la bóveda: en la MISMA pantalla del código, debajo. Es
   información para leer mientras esperas, no una pregunta que responder. */
.what { border-top: 1px solid #1e2a3d; margin-top: 8px; padding-top: 14px; text-align: left; width: 100%; }
.what p { margin: 4px 0 0; }
.cmd { font-size: 12px; color: #8ea0b8; }
.cmd code { background: #131c2b; border-radius: 6px; padding: 2px 6px; font-family: ui-monospace, monospace; color: #bfe0ff; }
.two-accounts, .announce { background: #101826; border: 1px solid #24344d; display: flex; flex-direction: column; gap: 6px; align-items: flex-start; }
.banner.info { background: #10203a; color: #9cc4ff; }
.banner.warn { background: #2a2310; color: #ffd98a; }
/* Aviso junto al código de aprobación: es la única defensa contra que te lo dicten. */
.muted.warn { color: #ffd98a; }
.members { list-style: none; padding: 0; margin: 0; display: grid; gap: 10px; }
.member { background: #0f1725; border: 1px solid #1e2a3d; border-radius: 12px; padding: 12px 14px; }
.who { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }
.tag { font-size: 11px; background: #1b2536; color: #9fb0c9; border-radius: 999px; padding: 2px 8px; }
.tag.master { background: #1d3350; color: #9cc4ff; }
.tag.svc { background: #2a2310; color: #ffd98a; }
/* «Sin acceso»: está en el acta pero no puede entrar. Es un aviso, y se ve como tal. */
.tag.out { background: #2a1113; color: #ff9aa2; }
.svc-note { font-size: 12px; margin: 8px 0 0; }
.caps { display: flex; gap: 6px; flex-wrap: wrap; margin: 10px 0 0; }
.cap { font-size: 12px; border-radius: 999px; padding: 4px 10px; border: 1px solid #2a3a52; background: transparent; color: #7d8fa8; cursor: pointer; }
.cap.on { background: #14304a; color: #bfe0ff; border-color: #2f5f8f; }
.cap:disabled { cursor: default; opacity: .75; }
.acts { display: flex; gap: 8px; margin-top: 10px; flex-wrap: wrap; }
.confirm { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 10px; font-size: 13px; color: #ffd98a; }
.btn { border-radius: 10px; padding: 8px 14px; border: 1px solid #2a3a52; background: #17263c; color: #dbe7f7; cursor: pointer; font: inherit; }
.btn.ghost { background: transparent; }
.btn.danger { background: #2a1113; border-color: #5a2027; color: #ff9aa2; }
.btn.sm { padding: 5px 10px; font-size: 13px; }
.btn:disabled { opacity: .5; cursor: default; }
.row { display: flex; gap: 8px; flex-wrap: wrap; align-items: center; margin: 10px 0; }
textarea { width: 100%; background: #0d1521; color: #dbe7f7; border: 1px solid #223047; border-radius: 10px; padding: 10px; font-family: ui-monospace, monospace; font-size: 12px; }
.codebox { border-color: #2f5f8f; text-align: center; align-items: center; }
.digits { font-size: clamp(38px, 12vw, 56px); letter-spacing: .18em; font-family: ui-monospace, monospace; color: #bfe0ff; margin: 6px 0; }
.qrbox { background: #fff; padding: 12px; border-radius: 12px; width: max-content; margin: 12px 0; }
.qrbox :deep(svg) { width: 220px; height: 220px; display: block; }
/* El enlace de la invitación: largo, así que se parte en vez de desbordar, y el botón
   de copiar no se encoge nunca. */
.invite { display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin: 4px 0 12px; }
.invite .url {
  background: #131c2b; border-radius: 6px; padding: 6px 8px; font-size: 12px;
  font-family: ui-monospace, monospace; color: #bfe0ff; overflow-wrap: anywhere;
  max-width: 100%; flex: 1 1 260px;
}
.invite .btn { flex: 0 0 auto; }
.scanbox { margin: 10px 0; }
.scanbox video { width: 100%; max-width: 360px; border-radius: 12px; background: #000; }
.pending { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; background: #10203a; border-radius: 10px; padding: 10px 12px; margin: 10px 0; }
.pending input { background: #0d1521; color: #dbe7f7; border: 1px solid #223047; border-radius: 8px; padding: 6px 10px; width: 140px; font-family: ui-monospace, monospace; }
details summary { cursor: pointer; color: #9fb0c9; margin: 10px 0 6px; }
</style>
