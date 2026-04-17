#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)
MEMBRANE_SRC="${HOME}/.membrane/src"

# On macOS, membrane uses a dedicated Colima profile. Matches the behavior
# in pkg/membrane/membrane.go.
if [ "$(uname)" = "Darwin" ]; then
    export DOCKER_CONTEXT=colima-membrane
fi

echo "Linking ~/.membrane/src -> ${REPO_ROOT}"
ln -sfn "$REPO_ROOT" "$MEMBRANE_SRC"

echo "Building membrane-agent..."
docker build -t membrane-agent "${REPO_ROOT}/docker/agent/"

echo "Building membrane-handler..."
docker build -t membrane-handler "${REPO_ROOT}/docker/handler/"

echo "Building membrane binary..."
go build -o "${REPO_ROOT}/membrane" "${REPO_ROOT}/cmd/membrane"

"${REPO_ROOT}/membrane" "$@"
