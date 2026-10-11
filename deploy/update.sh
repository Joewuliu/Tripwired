#!/usr/bin/env bash
# Deploy what is checked out: build, start, and make sure every container runs its newest image.
#
#   cd ~/tripwire && git pull && bash deploy/update.sh
#
# "docker compose up -d --build" should recreate a container whose image was rebuilt, but it has
# left the old caddy container running (IMAGE shows a bare sha256). So after starting, each
# container's image is compared with the image just built, and a stale one is recreated alone.
set -euo pipefail
cd "$(dirname "$0")/.."

docker compose up -d --build --remove-orphans

for service in analyzer gateway caddy; do
  container="$(docker compose ps -q "$service")"
  built="$(docker image inspect -f '{{.Id}}' "tripwire-$service")"
  running=""
  [ -n "$container" ] && running="$(docker inspect -f '{{.Image}}' "$container")"
  if [ "$running" != "$built" ]; then
    echo "$service is not on its newest image: recreating it"
    docker compose up -d --force-recreate --no-deps "$service"
  fi
done

docker image prune -f >/dev/null
docker compose ps --format 'table {{.Service}}\t{{.Image}}\t{{.Status}}'
