#!/usr/bin/env bash

#TEST_OUTPUT_FILE="${HOME}/tests_output/config_diffs.txt"
rm "/tmp/confs/out.txt"
TEST_OUTPUT_FILE="/tmp/confs/out.txt"

function compare_configs {
    folder_a=$1
    folder_b=$2
    binaries=(server connector translator addzone webconfig rollback keymaker poisonrecordmaker authmanager rotate)
    for cmd in "${binaries[@]}"; do
     cmp ${folder_a}/acra-${cmd}.yaml ${folder_b}/acra-${cmd}.yaml 1>>${TEST_OUTPUT_FILE}
     cmp_status="$?"
     if [[ "${cmp_status}" != "0" ]]; then
        status=1
     fi
    done
    cat ${TEST_OUTPUT_FILE}
}

temp_configs=`mktemp -d`
echo "generate fresh configs to temporary folder ${temp_configs}"
bash configs/regenerate.sh ${temp_configs}

status=0
compare_configs configs ${temp_configs}
echo "remove temporary folder ${temp_configs}"
rm -rf ${temp_configs}
exit ${status}