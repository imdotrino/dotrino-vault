#!/bin/sh
# La shell de la demo (`demo.mjs`): con el entorno VACÍO, sin las credenciales de la función.
mkdir -p /tmp/home
cd /tmp/home
exec env -i HOME=/tmp/home PATH=/usr/local/bin:/usr/bin:/bin TERM="${TERM:-xterm-256color}" LANG=C.UTF-8 PS1='demo:\w\$ ' /bin/bash --norc --noediting -i
