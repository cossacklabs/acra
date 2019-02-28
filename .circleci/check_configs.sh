#!/usr/bin/env bash
function compare_configs {
    folder_a=$1
    folder_b=$2
    binaries=(server connector translator addzone webconfig rollback keymaker poisonrecordmaker authmanager rotate)
    status=0
    for cmd in "${binaries[@]}"; do
     cmp ${folder_a}/acra-${cmd}.yaml ${folder_b}/acra-${cmd}.yaml
     status="$?"
     if [[ "${status}" != "0" ]]; then
        echo "acra-${cmd} differ"
        status=1
     fi
    done
    exit ${status}
}

temp_configs=`mktemp -d`
echo "generate fresh configs to temporary folder ${temp_configs}"
bash configs/regenerate.sh ${temp_configs}

compare_configs configs ${temp_configs}