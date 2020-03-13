#!/usr/bin/env bash

binaries=(server connector translator addzone webconfig rollback keymaker migrate-keys poisonrecordmaker authmanager rotate)

args="--dump_config"


for cmd in "${binaries[@]}"; do
 if [[ "$#" == "1" ]]; then
    args="--dump_config --config_file=$1/acra-${cmd}.yaml"
 fi
 go run ./cmd/acra-${cmd}/*.go `echo ${args}`
done
