<script setup>
/**
 * LAS VARIABLES DE UN DESTINO — un grupo (`ns:<grupo>`) o un aparato (`dev:<pubkey>`).
 *
 * Es un componente y no dos copias porque las variables se administran en DOS sitios, y
 * a propósito: las de un servicio viven en la fila de ese servicio, junto a su nombre y
 * sus permisos, que es donde se ve de quién son; las de un grupo, dentro del apartado de
 * su grupo. Antes había un desplegable «¿Dónde?» delante de un único formulario, y elegir
 * el destino en una lista era adivinar.
 *
 * TODAS las filas son la MISMA fila: nombre, valor y privada. Lo único que distingue a una
 * variable que ya existe es que su nombre no se puede cambiar (renombrar no existe: sería
 * crear otra y dejar la vieja). Se edita donde se lee, sin abrir un cajón aparte que te
 * hacía perder de vista cuál estabas tocando.
 *
 * UN SOLO BOTÓN AL FINAL, y esa es la regla que ordena esta pantalla. Antes cada fila
 * tenía su «Guardar», y guardar es lo que hace que la bóveda avise a la aplicación de que
 * su configuración cambió: cargar seis variables eran seis avisos, o sea seis reinicios,
 * y la aplicación arrancaba con lo que hubiera puesto hasta ese momento mientras se
 * seguía escribiendo el resto. Aquí se edita todo lo que haga falta —cambiar valores,
 * añadir filas, pegar un bloque entero— y se confirma UNA vez: la bóveda las guarda
 * juntas y la aplicación se reinicia una sola vez, con todo puesto.
 *
 * AÑADIR VARIAS NO ES UNA PANTALLA APARTE. Hay SIEMPRE una fila en blanco al final y, en
 * cuanto empiezas a llenarla, nace otra debajo: cargar seis es teclear seis veces, sin
 * pulsar «Agregar» entre una y otra. Y el `.env` que ya tienes se **pega en el campo del
 * nombre**: si lo pegado trae `=` o varias líneas, se reparte en filas ahí mismo. Antes
 * eso era un botón «Agregar variable» más un cuadro de texto suelto con su propio botón
 * de «repartir» — tres controles para lo que ahora hace el propio campo.
 *
 * Lo que se puede hacer no cambia (docs/consola-remota.md §2): ver el valor si es pública,
 * darle uno nuevo siempre —aunque no puedas leerlo, que es rotar a ciegas— y borrar no.
 */
import { ref, computed, watch } from 'vue'
import { parseEnvText } from '../../lib/src/envtext.js'
import { isValidVarKey } from '../../lib/src/protocol.js'

const props = defineProps({
  target: { type: String, required: true }, // 'ns:<grupo>' | 'dev:<pubkey>'
  tid: { type: String, required: true },    // lo que va en los data-testid (grupo o id del aparato)
  rows: { type: Array, default: () => [] },
  t: { type: Object, required: true },
  busy: { type: String, default: '' },
  save: { type: Function, required: true }, // ({ target, items }) → Promise
  // Si a este destino se le pueden AÑADIR variables. Falso para un aparato que no es un
  // servicio: la bóveda solo se las guarda a quien las lee, así que ofrecer el formulario
  // sería un botón que siempre falla. Lo que ya tuviera se sigue viendo y se puede cambiar.
  add: { type: Boolean, default: true }
})

const borrador = ref([])   // las que ya existen, con lo tecleado encima
const nuevas = ref([])     // las que se están añadiendo, aún sin confirmar
const errorPegado = ref('')

const filaVacia = () => ({ key: '', value: '', priv: true })
/** Una fila nueva «cuenta» en cuanto tiene algo escrito; la última en blanco es el hueco. */
const usada = (n) => !!n.key.trim() || !!n.value

/**
 * El borrador se rehace con cada lista que llega de la bóveda (confirmar recarga), así que
 * lo que se ve en los campos es siempre lo guardado. De una privada no llega el valor:
 * su campo nace vacío y lo que escribas ahí es el valor NUEVO.
 */
watch(() => props.rows, (rows) => {
  borrador.value = (rows || []).map((r) => {
    const value = r.public ? (r.value ?? '') : ''
    return { key: r.key, value, priv: !r.public, era: { value, priv: !r.public } }
  })
  nuevas.value = props.add ? [filaVacia()] : []
  errorPegado.value = ''
}, { immediate: true, deep: true })

/**
 * El hueco del final se repone solo: escribes en la última fila y aparece otra debajo. Es
 * lo que quita el botón «Agregar variable» — cargar seis variables es teclear, no alternar
 * entre teclear y pulsar. Nunca hay más de una en blanco al final.
 */
watch(nuevas, (ns) => {
  if (!props.add) return
  const ultima = ns[ns.length - 1]
  if (!ultima || usada(ultima)) nuevas.value = [...ns, filaVacia()]
}, { deep: true })

const cambiada = (d) => d.value !== d.era.value || d.priv !== d.era.priv
/**
 * Confirmar exige un valor, siempre. Por eso una privada no se puede volver pública sin
 * teclearlo: quien administra a distancia no puede destapar un secreto que no conoce,
 * solo reemplazarlo (y eso queda en la bitácora).
 */
const listas = computed(() => [
  ...borrador.value.filter((d) => cambiada(d) && !!d.value),
  ...nuevas.value.filter((d) => isValidVarKey(d.key.trim().toUpperCase()) && !!d.value)
])

/** Lo que está a medias: una fila con nombre y sin valor, o al revés. No se puede confirmar. */
const aMedias = computed(() => [
  ...borrador.value.filter((d) => cambiada(d) && !d.value),
  ...nuevas.value.filter((d) => (!!d.key.trim() || !!d.value) && !(isValidVarKey(d.key.trim().toUpperCase()) && !!d.value))
].length > 0)

const puedeConfirmar = computed(() => !!listas.value.length && !aMedias.value && !props.busy)

const quitarFila = (i) => { nuevas.value = nuevas.value.filter((_, n) => n !== i) }

/**
 * Pegar la configuración tal como ya la tienes (un `.env`) EN EL CAMPO DEL NOMBRE: cada
 * línea se convierte en una fila más, editable como las demás. No se guarda nada todavía
 * — sigue mandando el botón.
 *
 * Solo se intercepta si lo pegado trae `=` o un salto de línea; un nombre suelto se pega
 * como en cualquier campo. Y solo en el campo del NOMBRE, nunca en el del valor: un
 * secreto puede llevar `=` (base64 termina en `==`) y partirlo lo estropearía en silencio.
 */
function pegar (ev, idx) {
  const texto = ev.clipboardData?.getData('text') || ''
  if (!/[\n=]/.test(texto)) return
  ev.preventDefault()
  errorPegado.value = ''
  const { items, errors } = parseEnvText(texto)
  if (errors.length) {
    errorPegado.value = props.t.var_paste_err?.(errors[0]) || 'error'
    return
  }
  const destino = [...nuevas.value]
  let hueco = idx
  for (const it of items) {
    // Si la variable ya está arriba, lo pegado es su valor NUEVO: se escribe en su fila en
    // vez de duplicarla (dos filas con el mismo nombre serían una trampa).
    const fila = borrador.value.find((d) => d.key === it.key)
    if (fila) { fila.value = it.value; continue }
    const n = destino.find((d) => d.key.trim().toUpperCase() === it.key)
    if (n) { n.value = it.value; continue }
    // La primera cae en la fila donde se pegó (si estaba en blanco); las demás, detrás.
    if (hueco !== null && destino[hueco] && !usada(destino[hueco])) {
      destino[hueco] = { key: it.key, value: it.value, priv: true }
      hueco = null
    } else destino.push({ key: it.key, value: it.value, priv: true })
  }
  nuevas.value = destino
}

/** UNA llamada con todo dentro: la bóveda las guarda juntas y avisa una sola vez. */
const confirmar = () => props.save({
  target: props.target,
  items: listas.value.map((d) => ({ key: (d.key || '').trim().toUpperCase(), value: d.value, public: !d.priv }))
})
</script>

<template>
  <div class="varlist">
    <div v-for="d in borrador" :key="d.key" class="varrow" :data-var="tid + '/' + d.key">
      <!-- El nombre se queda: renombrar no existe (sería crear otra y dejar la vieja). -->
      <input class="k" type="text" :value="d.key" disabled :data-testid="'var-key-' + tid + '-' + d.key" />
      <input v-model="d.value" :type="d.priv ? 'password' : 'text'" autocomplete="off"
             :placeholder="d.era.priv ? '••••••' : t.var_value_ph"
             :data-testid="'var-value-' + tid + '-' + d.key" />
      <label class="chk">
        <input v-model="d.priv" type="checkbox" :data-testid="'var-private-' + tid + '-' + d.key" />
        {{ t.var_private_ask }}
      </label>
      <span v-if="cambiada(d)" class="tag">{{ t.var_pending }}</span>
    </div>

    <template v-if="add">
      <div v-for="(n, idx) in nuevas" :key="'n' + idx" class="varrow nueva" :data-testid="'var-new-' + tid + '-' + idx">
        <!-- Aquí también se PEGA el `.env` entero: si trae `=` o varias líneas, se reparte. -->
        <input v-model="n.key" class="k" type="text" :placeholder="t.var_key_ph"
               :data-testid="'var-new-key-' + tid + '-' + idx" @paste="pegar($event, idx)" />
        <input v-model="n.value" :type="n.priv ? 'password' : 'text'" autocomplete="off"
               :placeholder="t.var_value_ph" :data-testid="'var-new-value-' + tid + '-' + idx" />
        <!-- Nace PRIVADA, y la casilla lo dice con esa palabra: «que su valor se pueda ver
             desde aquí» obligaba a traducir mentalmente una frase para marcar lo normal. -->
        <label class="chk">
          <input v-model="n.priv" type="checkbox" :data-testid="'var-new-private-' + tid + '-' + idx" />
          {{ t.var_private_ask }}
        </label>
        <!-- La fila en blanco del final no se quita: es el hueco, no una fila de más. -->
        <button v-if="usada(n)" class="btn sm ghost" :data-testid="'var-new-drop-' + tid + '-' + idx"
                @click="quitarFila(idx)">×</button>
      </div>
      <!-- Lo único que queda del cuadro de texto: decir dónde se pega. Sin esta línea el
           gesto no se descubre, y no cabe dentro del campo sin recortar el ejemplo. -->
      <p class="hint pista" :data-testid="'var-paste-hint-' + tid">{{ t.var_paste_hint }}</p>
      <p v-if="errorPegado" class="err" :data-testid="'var-paste-error-' + tid">{{ errorPegado }}</p>
    </template>

    <!-- EL botón. Uno solo, para todo lo de arriba: así la aplicación recibe un único
         aviso de cambio y se reinicia una vez, con la configuración entera. -->
    <div class="confirmar">
      <button class="btn" :data-testid="'var-save-' + tid" :disabled="!puedeConfirmar" @click="confirmar">
        {{ listas.length ? t.var_save_n(listas.length) : t.var_save }}
      </button>
      <span v-if="aMedias" class="hint">{{ t.var_incomplete }}</span>
      <span v-else-if="listas.length" class="hint">{{ t.var_save_hint }}</span>
    </div>
  </div>
</template>

<style scoped>
/* Misma paleta que la consola: el componente vive dentro de ella y no debe notarse
   que es otro archivo (los estilos `scoped` del padre no cruzan hasta aquí). */
.varlist { margin: 6px 0 0; }
.varrow { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 6px 0 0 12px; }
/* Las nuevas se separan del bloque de las guardadas, pero entre ellas van juntas: son
   una lista que crece mientras tecleas, no fichas sueltas. */
.varrow.nueva { margin-top: 14px; }
.varrow.nueva + .varrow.nueva { margin-top: 6px; }
.chk { display: flex; gap: 6px; align-items: center; font-size: 13px; color: #9fb3c8; }
.confirmar { display: flex; gap: 10px; align-items: center; flex-wrap: wrap; margin: 12px 0 0 12px; }
.hint { font-size: 12px; color: #9fb3c8; }
.pista { margin: 6px 0 0 12px; }
.err { margin: 6px 0 0 12px; font-size: 13px; color: #ffb4a2; }
.tag { font-size: 12px; color: #ffd79a; }
input[type="text"], input[type="password"] {
  background: #0d1521; color: #dbe7f7; border: 1px solid #223047;
  border-radius: 8px; padding: 6px 10px; font: inherit; font-size: 13px; min-width: 0; flex: 1 1 160px;
}
/* El nombre, en monoespaciada y sin encogerse: es lo que se busca al leer la lista. */
input.k { font-family: ui-monospace, monospace; flex: 0 1 220px; }
input:disabled { color: #9fb0c9; background: #101927; border-style: dashed; }
.btn { border-radius: 10px; padding: 8px 14px; border: 1px solid #2a3a52; background: #17263c; color: #dbe7f7; cursor: pointer; font: inherit; }
.btn.sm { padding: 5px 10px; font-size: 13px; }
.btn.ghost { background: transparent; border-color: #223047; color: #9fb3c8; }
.btn:disabled { opacity: .5; cursor: default; }
</style>
