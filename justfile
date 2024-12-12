
GREEN  := "\\u001b[32m"
RESET  := "\\u001b[0m\\n"
CHECK  := "\\xE2\\x9C\\x94"

set shell := ["bash", "-uc"]

default:
  @just --list

build opts = "":
  docker compose build {{opts}}
  @printf " {{GREEN}}{{CHECK}} Successfully built! {{CHECK}} {{RESET}}"

pull:
  @git pull

up extra='': build
  docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d --force-recreate {{extra}}
  @printf " {{GREEN}}{{CHECK}} Images Started {{CHECK}} {{RESET}}"

push: build
  docker compose push
  export VERSION=$(git rev-parse --short HEAD) && docker compose build && docker compose push
  @printf " {{GREEN}}{{CHECK}} Images Pushed {{CHECK}} {{RESET}}"

prod image version='latest':
  export VERSION={{version}} && docker compose pull
  export VERSION={{version}} && docker rollout {{image}}
  @printf " {{GREEN}}{{CHECK}} Images Started {{CHECK}} {{RESET}}"

rollback image:
  export VERSION=$(docker image ls --filter before=manifoldlabs/targon-hub-{{image}}:latest --filter reference=manifoldlabs/targon-hub-{{image}} --format "{{{{.Tag}}" | head -n 1) && docker rollout {{image}}

history image:
  docker image ls --filter before=manifoldlabs/targon-hub-{{image}}:latest --filter reference=manifoldlabs/targon-hub-{{image}}

down:
  @docker compose down
