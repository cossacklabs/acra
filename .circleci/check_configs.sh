#!/usr/bin/env bash

function compare_configs() {
    folder_a=$1
    folder_b=$2
    binaries=(server connector translator addzone webconfig rollback keymaker poisonrecordmaker authmanager rotate)
    for cmd in "${binaries[@]}"; do
     cmp ${folder_a}/acra-${cmd}.yaml ${folder_b}/acra-${cmd}.yaml
     cmp_status="$?"
     if [[ "${cmp_status}" != "0" ]]; then
        status=1
     fi
    done
}
# use go from GOROOT instead installed in system
PATH=$GOROOT/bin:$PATH
temp_configs=`mktemp -d`
bash configs/regenerate.sh ${temp_configs}

status=0
compare_configs configs ${temp_configs}

rm -rf ${temp_configs}
exit ${status}