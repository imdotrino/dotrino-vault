# @dotrino/env

Tus credenciales del vault en vez del `.env`. Es el mismo `dotrino-env` de
[`@dotrino/vault`](https://www.npmjs.com/package/@dotrino/vault), publicado con nombre
propio para llamarlo corto:

```sh
npx -y @dotrino/env enroll --ns miapp --code <código>   # una vez (invitación de `dotrino-vault pair`)
npx -y @dotrino/env run --ns miapp -- node app.js       # variables solo en memoria del hijo
npx -y @dotrino/env ssh-agent --ns ssh                  # llaves SSH solo en memoria
```

MIT.
