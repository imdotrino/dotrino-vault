/**
 * EL PASEO POR LOS PERFILES QUE APRUEBAN: la decisión, aparte de la pantalla.
 *
 * El timbre no dice a qué perfil llamó —viaja por FCM, o sea por Google, y ahí no se mete
 * nada que identifique la cuenta— así que con varios perfiles que aprueban, la única forma
 * de saber dónde está el pedido es MIRAR en cada uno. Cambiar de perfil recarga la página
 * (no es reactivo, por diseño), así que el paseo es una máquina de estados que vive entre
 * recargas: por eso la decisión está aquí, en una función pura que se puede probar sin
 * navegador, y no enredada con el `location.reload()` que la ejecuta.
 *
 * Lo que garantiza: cada perfil se prueba UNA vez (no hay forma de dar vueltas) y, si
 * ninguno tenía nada, se vuelve a la cuenta desde la que se entró — dejarte en la última
 * que se miró sería un efecto secundario de mirar.
 *
 * @param {Object} e
 * @param {string|null} e.aqui       perfil abierto ahora
 * @param {string|null} e.from       perfil desde el que empezó el paseo (null si empieza aquí)
 * @param {string[]} e.tried         perfiles ya mirados
 * @param {string[]} e.approvers     perfiles que pueden aprobar, en el orden en que se ofrecen
 * @param {boolean} e.hasPending     ¿hay un pedido en el perfil abierto?
 * @returns {{ go: string|null, back: string|null, tried: string[], done: boolean, nothingAnywhere: boolean }}
 */
export function walkStep ({ aqui = null, from = null, tried = [], approvers = [], hasPending = false } = {}) {
  const vistos = tried.includes(aqui) || !aqui ? [...tried] : [...tried, aqui]
  // El pedido está aquí: el paseo termina donde tenía que terminar.
  if (hasPending) return { go: null, back: null, tried: vistos, done: true, nothingAnywhere: false }

  const siguiente = approvers.find((p) => !vistos.includes(p))
  if (siguiente) return { go: siguiente, back: null, tried: vistos, done: false, nothingAnywhere: false }

  // No queda ninguno por mirar. Si se empezó en otro perfil, se vuelve; y en cualquier caso
  // hay que DECIR que no había nada en ninguno, que es distinto de «no hay nada aquí».
  const volver = from && from !== aqui ? from : null
  return { go: null, back: volver, tried: vistos, done: !volver, nothingAnywhere: vistos.length > 1 }
}
