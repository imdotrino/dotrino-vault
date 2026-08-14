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
 * TODAS las filas son la MISMA fila: nombre, valor, privada y guardar. Lo único que
 * distingue a una variable que ya existe es que su nombre no se puede cambiar (renombrar
 * no existe: sería crear otra y dejar la vieja). Se edita donde se lee, sin abrir un
 * cajón aparte que te hacía perder de vista cuál estabas tocando.
 *
 * Lo que se puede hacer no cambia (docs/consola-remota.md §2): ver el valor si es pública,
 * darle uno nuevo siempre —aunque no puedas leerlo, que es rotar a ciegas— y borrar no.
 */
import { ref, watch } from 'vue'

const props = defineProps({
  target: { type: String, required: true }, // 'ns:<grupo>' | 'dev:<pubkey>'
  tid: { type: String, required: true },    // lo que va en los data-testid (grupo o id del aparato)
  rows: { type: Array, default: () => [] },
  t: { type: Object, required: true },
  busy: { type: String, default: '' },
  save: { type: Function, required: true }, // ({ target, key, value, isPublic }) → Promise
  // Si a este destino se le pueden AÑADIR variables. Falso para un aparato que no es un
  // servicio: la bóveda solo se las guarda a quien las lee, así que ofrecer el formulario
  // sería un botón que siempre falla. Lo que ya tuviera se sigue viendo y se puede cambiar.
  add: { type: Boolean, default: true }
})

const nueva = ref({ key: '', value: '', priv: true })
const borrador = ref([])

/**
 * El borrador se rehace con cada lista que llega de la bóveda (guardar recarga), así que
 * lo que se ve en los campos es siempre lo guardado. De una privada no llega el valor:
 * su campo nace vacío y lo que escribas ahí es el valor NUEVO.
 */
watch(() => props.rows, (rows) => {
  borrador.value = (rows || []).map((r) => {
    const value = r.public ? (r.value ?? '') : ''
    return { key: r.key, value, priv: !r.public, era: { value, priv: !r.public } }
  })
}, { immediate: true, deep: true })

const cambiada = (d) => d.value !== d.era.value || d.priv !== d.era.priv
/**
 * Guardar exige un valor, siempre. Por eso una privada no se puede volver pública sin
 * teclearlo: quien administra a distancia no puede destapar un secreto que no conoce,
 * solo reemplazarlo (y eso queda en la bitácora).
 */
const puede = (d) => cambiada(d) && !!d.value && !props.busy

const guardar = (d) => props.save({ target: props.target, key: d.key, value: d.value, isPublic: !d.priv })

const agregar = async () => {
  const n = nueva.value
  const key = n.key.trim().toUpperCase()
  if (!key || !n.value) return
  await props.save({ target: props.target, key, value: n.value, isPublic: !n.priv })
  nueva.value = { key: '', value: '', priv: true }
}
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
      <button class="btn sm" :data-testid="'var-save-' + tid + '-' + d.key"
              :disabled="!puede(d)" @click="guardar(d)">{{ t.var_save }}</button>
    </div>

    <div v-if="add" class="varrow nueva" :data-testid="'var-new-' + tid">
      <input v-model="nueva.key" class="k" type="text" :placeholder="t.var_key_ph"
             :data-testid="'var-new-key-' + tid" />
      <input v-model="nueva.value" :type="nueva.priv ? 'password' : 'text'" autocomplete="off"
             :placeholder="t.var_value_ph" :data-testid="'var-new-value-' + tid" />
      <!-- Nace PRIVADA, y la casilla lo dice con esa palabra: «que su valor se pueda ver
           desde aquí» obligaba a traducir mentalmente una frase para marcar lo normal. -->
      <label class="chk">
        <input v-model="nueva.priv" type="checkbox" :data-testid="'var-new-private-' + tid" />
        {{ t.var_private_ask }}
      </label>
      <button class="btn sm" :data-testid="'var-new-save-' + tid"
              :disabled="!nueva.key.trim() || !nueva.value || !!busy" @click="agregar">{{ t.var_add }}</button>
    </div>
  </div>
</template>

<style scoped>
/* Misma paleta que la consola: el componente vive dentro de ella y no debe notarse
   que es otro archivo (los estilos `scoped` del padre no cruzan hasta aquí). */
.varlist { margin: 6px 0 0; }
.varrow { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 6px 0 0 12px; }
.varrow.nueva { margin-top: 10px; }
.chk { display: flex; gap: 6px; align-items: center; font-size: 13px; color: #9fb3c8; }
input[type="text"], input[type="password"] {
  background: #0d1521; color: #dbe7f7; border: 1px solid #223047;
  border-radius: 8px; padding: 6px 10px; font: inherit; font-size: 13px; min-width: 0; flex: 1 1 160px;
}
/* El nombre, en monoespaciada y sin encogerse: es lo que se busca al leer la lista. */
input.k { font-family: ui-monospace, monospace; flex: 0 1 220px; }
input:disabled { color: #9fb0c9; background: #101927; border-style: dashed; }
.btn { border-radius: 10px; padding: 8px 14px; border: 1px solid #2a3a52; background: #17263c; color: #dbe7f7; cursor: pointer; font: inherit; }
.btn.sm { padding: 5px 10px; font-size: 13px; }
.btn:disabled { opacity: .5; cursor: default; }
</style>
