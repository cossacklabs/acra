#!/bin/bash

set -euo pipefail

FILE_ELF="$1"
DIR_CONTAINER="$2"

mkdir -p "$DIR_CONTAINER"

mapfile -t libs < <(ldd "$FILE_ELF" | grep '=>' | awk '{print $3}')
libs+=($(readelf -l "$FILE_ELF" | grep -Po "(?<=preter:\\s).+(?=\\])"))

for l in "${libs[@]}"; do
    mkdir -p "${DIR_CONTAINER}/$(dirname ${l})"
    cp -L "$l" "${DIR_CONTAINER}/${l}"
done
