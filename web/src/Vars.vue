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
 * Lo que se puede hacer con una variable no cambia: ver el valor si es pública, darle un
 * valor nuevo siempre (aunque no puedas leerla — rotar a ciegas es para lo que sirve), y
 * borrar no existe (docs/consola-remota.md §2).
 */
const props = defineProps({
  target: { type: String, required: true }, // 'ns:<grupo>' | 'dev:<pubkey>'
  tid: { type: String, required: true },    // lo que va en los data-testid (grupo o id del aparato)
  rows: { type: Array, default: () => [] },
  t: { type: Object, required: true },
  busy: { type: String, default: '' },
  save: { type: Function, required: true }  // ({ target, key, value, isPublic }) → Promise
})

import { ref } from 'vue'

const nueva = ref({ key: '', value: '', priv: true })
const editando = ref('')
const valor = ref('')

const empezar = (key) => { editando.value = key; valor.value = '' }

async function guardar () {
  const key = editando.value
  const value = valor.value
  if (!value) return
  editando.value = ''; valor.value = ''
  // Sin `isPublic`: cambiar el valor NO cambia quién lo puede ver. Que exponer un secreto
  // fuera el descuido de un guardado sería justo lo contrario de lo que hace esto.
  await props.save({ target: props.target, key, value })
}

async function agregar () {
  const n = nueva.value
  if (!n.key.trim() || !n.value) return
  const { key, value, priv } = { key: n.key.trim(), value: n.value, priv: n.priv }
  await props.save({ target: props.target, key, value, isPublic: !priv })
  nueva.value = { key: '', value: '', priv: true }
}
</script>

<template>
  <div class="varlist">
    <template v-for="v in rows" :key="v.key">
      <div class="varrow" :data-var="tid + '/' + v.key">
        <code>{{ v.key }}</code>
        <span v-if="v.public" class="val" :data-testid="'val-' + v.key">{{ v.value }}</span>
        <span v-else class="tag out">{{ t.var_private }}</span>
        <button class="btn ghost sm" :data-testid="'edit-' + tid + '-' + v.key"
                @click="empezar(v.key)">{{ t.var_change }}</button>
      </div>
      <!-- El valor nuevo se teclea PEGADO a su variable: así se ve cuál estás cambiando. -->
      <div v-if="editando === v.key" class="confirm varedit" :data-testid="'var-edit-' + tid">
        <span>{{ t.var_new_value(v.key) }}</span>
        <input v-model="valor" type="password" autocomplete="off" :data-testid="'var-edit-value-' + tid" />
        <button class="btn sm" :data-testid="'var-edit-save-' + tid" :disabled="!valor || !!busy"
                @click="guardar">{{ t.var_save }}</button>
        <button class="btn ghost sm" @click="editando = ''">{{ t.cancel }}</button>
      </div>
    </template>

    <div class="varnew" :data-testid="'var-new-' + tid">
      <input v-model="nueva.key" type="text" :placeholder="t.var_key_ph" :data-testid="'var-new-key-' + tid" />
      <input v-model="nueva.value" type="password" autocomplete="off" :placeholder="t.var_value_ph"
             :data-testid="'var-new-value-' + tid" />
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
.varrow .val { font-family: ui-monospace, monospace; font-size: 13px; word-break: break-all; }
.varnew { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin: 10px 0 0 12px; }
.varedit { margin-left: 12px; }
.chk { display: flex; gap: 6px; align-items: center; font-size: 13px; color: #9fb3c8; }
code { font-family: ui-monospace, monospace; font-size: 13px; background: #131c2b; border-radius: 6px; padding: 1px 6px; }
input[type="text"], input[type="password"] {
  background: #0d1521; color: #dbe7f7; border: 1px solid #223047;
  border-radius: 8px; padding: 6px 10px; font: inherit; font-size: 13px; min-width: 0; flex: 1 1 160px;
}
.tag { font-size: 11px; background: #1b2536; color: #9fb0c9; border-radius: 999px; padding: 2px 8px; }
.tag.out { background: #2a1113; color: #ff9aa2; }
.btn { border-radius: 10px; padding: 8px 14px; border: 1px solid #2a3a52; background: #17263c; color: #dbe7f7; cursor: pointer; font: inherit; }
.btn.ghost { background: transparent; }
.btn.sm { padding: 5px 10px; font-size: 13px; }
.btn:disabled { opacity: .5; cursor: default; }
.confirm { display: flex; gap: 8px; align-items: center; flex-wrap: wrap; margin-top: 10px; font-size: 13px; color: #ffd98a; }
</style>
