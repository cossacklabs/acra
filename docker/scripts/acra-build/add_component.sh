#!/bin/bash

set -euo pipefail

COMPONENT="$1"
CONTAINER="$2"

COMPONENT_BIN="${GOPATH}/bin/acra-${COMPONENT}"
DESTINATION_DIR="container.acra-${CONTAINER}"

/image.scripts/collect_dependencies.sh "$COMPONENT_BIN" "/${DESTINATION_DIR}"
cp "$COMPONENT_BIN" "/${DESTINATION_DIR}/"
