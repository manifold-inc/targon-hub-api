
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

prod: build
  docker compose up -d
  @printf " {{GREEN}}{{CHECK}} Images Started {{CHECK}} {{RESET}}"

down:
  @docker compose down
