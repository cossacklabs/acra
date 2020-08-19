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

for cmd in $(ls ./cmd/ | grep ^acra-); do
    if [[ $# == 1 ]]; then
        extra="--config_file=$1/${cmd}.yaml"
    fi
    if [[ -f ./$cmd ]]; then
        ./$cmd $args $extra
    else
        go run ./cmd/$cmd $args $extra
    fi
done
