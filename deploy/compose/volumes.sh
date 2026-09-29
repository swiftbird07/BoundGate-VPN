#!/bin/sh
# The lab's separated nodes keep their state in volumes of the VM
# (docker-compose.yml, `volumes`). A lab from before has it in
# state/<service>, a directory of the Mac: this moves it into the volume,
# once, so that the nodes keep their keys and stay who the control plane
# knows. Run by `make compose-up` between creating the containers and
# starting them.
set -eu
cd "$(dirname "$0")"
COMPOSE="docker compose -f docker-compose.yml"
for s in hub1 node-a node-r; do
  [ -f "state/$s/device.key" ] || continue
  c=$($COMPOSE ps -aq "$s")
  [ -n "$c" ] || continue
  docker run --rm --network none --volumes-from "$c" -v "$PWD/state/$s:/from:ro" \
    --entrypoint sh "$(docker inspect --format '{{.Config.Image}}' "$c")" -c '
      cd /var/lib/boundgate
      [ -e .moved ] || [ -e device.key ] && exit 0
      cp -a /from/. . && chown -R 0:0 . && chmod 700 . && touch .moved && echo "moved the state of '"$s"' into its volume"'
done
