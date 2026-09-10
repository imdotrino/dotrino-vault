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
 * @param {boolean} e.hasPending    ¿hay un pedido en el perfil abierto?
 * @param {boolean} e.justFinished   este arranque ES la vuelta a casa de un paseo que acabó
 * @returns {{ go: string|null, back: string|null, tried: string[], done: boolean, nothingAnywhere: boolean }}
 */
export function walkStep ({ aqui = null, from = null, tried = [], approvers = [], hasPending = false, justFinished = false } = {}) {
  // UN PASEO QUE ACABA DE TERMINAR NO SE VUELVE A EMPEZAR, y este freno va AQUÍ y no en la
  // pantalla: la vuelta a casa es una recarga más, así que al montar de nuevo el paseo veía
  // su memoria ya borrada, se creía nuevo y salía otra vez al otro perfil — que a su vez
  // acababa devolviéndote aquí. La pantalla rotaba entre cuentas para siempre.
  //
  // Quien llama solo tiene que decir «vengo de terminar uno» (la marca que dejó la última
  // vuelta); decidir es de esta función, que es la que está probada.
  if (justFinished) return { go: null, back: null, tried: [...tried], done: true, nothingAnywhere: true }
  // SIN SABER DÓNDE ESTAMOS NO SE ANDA. Si no hay perfil abierto que reconocer, la lista de
  // mirados no puede crecer, y un paseo que no avanza es un paseo que no termina: saldría al
  // primer perfil que aprueba una y otra vez. Se para y se dice enseñando lo que haya.
  if (!aqui) return { go: null, back: null, tried: [...tried], done: true, nothingAnywhere: false }
  const vistos = tried.includes(aqui) ? [...tried] : [...tried, aqui]
  // El pedido está aquí: el paseo termina donde tenía que terminar.
  if (hasPending) return { go: null, back: null, tried: vistos, done: true, nothingAnywhere: false }

  const siguiente = approvers.find((p) => !vistos.includes(p))
  if (siguiente) return { go: siguiente, back: null, tried: vistos, done: false, nothingAnywhere: false }

  // No queda ninguno por mirar. Si se empezó en otro perfil, se vuelve; y en cualquier caso
  // hay que DECIR que no había nada en ninguno, que es distinto de «no hay nada aquí».
  const volver = from && from !== aqui ? from : null
  return { go: null, back: volver, tried: vistos, done: !volver, nothingAnywhere: vistos.length > 1 }
}
