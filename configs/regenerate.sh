#!/usr/bin/env bash
#
# Regenerate example configuration files.
#
# Run as
#
#     ./configs/regenerate.sh [dst-dir]
#
# from repository root. If dst-dir is not specified then configs are written
# into the default directory (./configs).

args="--dump_config"
extra=
BINARY_FOLDER=${BINARY_FOLDER:-./cmd}

for cmd in $(ls ./cmd/ | grep ^acra-); do
    if [[ $# == 1 ]]; then
        extra="--config_file=$1/${cmd}.yaml"
    fi
    # If there is already a binary in the repository root then use it as is,
    # otherwise use "go run" to compile and run it. The binaries are present
    # during integration tests, not rebuilding every time speeds up the tests.
    if [[ -f "${BINARY_FOLDER}/${cmd}" ]]; then
        "${BINARY_FOLDER}/${cmd}" $args $extra
    else
        go run ./cmd/$cmd $args $extra
    fi
done
