#!/usr/bin/env bash
set -o pipefail

export TEST_ACRASERVER_PORT=6000
export TEST_CONNECTOR_PORT=7000
export TEST_CONNECTOR_COMMAND_PORT=8000
export TEST_DB_USER=test
export TEST_DB_USER_PASSWORD=test
export TEST_DB_NAME=test
export GOPATH=$HOME/$GOPATH_FOLDER;
# cirecle ci has timeout 10 minutes without output after that it stop execution
# set timeout 8 minutes to give a time to re-start tests execution
export TEST_RUN_TIMEOUT=480 # 8 minutes (8 * 60)

export TEST_OUTPUT_FOLDER="${HOME}/tests_output"
mkdir -p ${TEST_OUTPUT_FOLDER}

cd $HOME/project
# set correct permissions for ssl keys here because git by default recognize changing only executable bit
# http://git.661346.n2.nabble.com/file-mode-td6467904.html#a6469081
# https://stackoverflow.com/questions/11230171/git-is-changing-my-files-permissions-when-i-push-to-server/11231682#11231682
find tests/ssl -name "*.key" -type f -exec chmod 0600 {} \;
for version in $VERSIONS; do
    echo "-------------------- Testing Go version $version"

    export TEST_ACRASERVER_PORT=$(expr ${TEST_ACRASERVER_PORT} + 1);
    export TEST_CONNECTOR_PORT=$(expr ${TEST_CONNECTOR_PORT} + 1);
    export TEST_CONNECTOR_COMMAND_PORT=$(expr ${TEST_CONNECTOR_COMMAND_PORT} + 1);
    export GOROOT=$HOME/go_root_$version/go;
    export PATH=$GOROOT/bin/:$PATH;

    # remove built packages with another golang version and force to rebuild
    rm -rf $GOPATH/pkg

    
    echo "--------------------  Testing with TEST_TLS=${TEST_TLS}"

    for iteration in {1..3}; do
        context="${iteration}-golang-${version}-tls-${TEST_TLS}"
        export TEST_XMLOUTPUT="${TEST_OUTPUT_FOLDER}/${context}.xml"
        LOG_OUTPUT="${TEST_OUTPUT_FOLDER}/${context}.log"
        timeout ${TEST_RUN_TIMEOUT} python3 tests/test.py -v | tee "${LOG_OUTPUT}";
        status="$?"
        if [[ "${status}" != "0" ]]; then
            echo "${context}. status=${status}" >> "$FILEPATH_ERROR_FLAG";
            continue
        else
            echo "no errors";
            if [[ "${iteration}" != "1" ]]; then
                # if test run successful after retries then copy retries log to folder that will be available on circleci ui
                cp "${FILEPATH_ERROR_FLAG}" "${TEST_OUTPUT_FOLDER}";
                rm "${FILEPATH_ERROR_FLAG}";
            fi
            break
        fi
    done
done
