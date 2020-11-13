#!/usr/bin/env bash
set -o pipefail

export TEST_ACRASERVER_PORT=6000
export TEST_CONNECTOR_PORT=7000
export TEST_CONNECTOR_COMMAND_PORT=8000
export TEST_OCSP_SERVER_PORT=8888
export TEST_CRL_HTTP_SERVER_PORT=8889
echo "Using TEST_DB_USER=$TEST_DB_USER"
echo "Using TEST_DB_USER_PASSWORD=$TEST_DB_USER_PASSWORD"
echo "Using TEST_DB_NAME=$TEST_DB_NAME"
echo "Using TEST_OCSP_SERVER_PORT=$TEST_OCSP_SERVER_PORT (for TLS only)"
echo "Using TEST_CRL_HTTP_SERVER_PORT=$TEST_CRL_HTTP_SERVER_PORT (for TLS only)"

# cirecle ci has timeout 10 minutes without output after that it stop execution
# set timeout 8 minutes to give a time to re-start tests execution
export TEST_RUN_TIMEOUT=480 # 8 minutes (8 * 60)

export TEST_OUTPUT_FOLDER="${HOME}/tests_output"
mkdir -p ${TEST_OUTPUT_FOLDER}

# set correct permissions for ssl keys here because git by default recognize changing only executable bit
# http://git.661346.n2.nabble.com/file-mode-td6467904.html#a6469081
# https://stackoverflow.com/questions/11230171/git-is-changing-my-files-permissions-when-i-push-to-server/11231682#11231682
find tests/ssl -name "*.key" -type f -exec chmod 0600 {} \;

OLD_PATH="$PATH"

if [ -z "$GO_VERSIONS" ]; then
    # extract default Go version from $GOROOT
    GO_VERSIONS="$(readlink $GOROOT)"
fi

for go_version in $GO_VERSIONS; do
    export GOROOT="/usr/local/lib/go/$go_version"

    if [ ! -d $GOROOT ]; then
        echo "Error: Go $go_version is not installed, $GOROOT does not exist"
        exit 1
    fi

    export PATH="$GOROOT/bin:$OLD_PATH"

    echo "-------------------- Testing $(go version) at $(which go)"
    echo "GOROOT=$GOROOT"
    echo "PATH=$PATH"

    export TEST_ACRASERVER_PORT=$(expr ${TEST_ACRASERVER_PORT} + 1);
    export TEST_CONNECTOR_PORT=$(expr ${TEST_CONNECTOR_PORT} + 1);
    export TEST_CONNECTOR_COMMAND_PORT=$(expr ${TEST_CONNECTOR_COMMAND_PORT} + 1);

    # remove built packages with another golang version and force to rebuild
    go clean -i -cache -testcache | true
    go mod download


    echo "-------------------- Testing with TEST_TLS=${TEST_TLS}"

    for iteration in {1..3}; do
        context="${iteration}-golang-${go_version}-tls-${TEST_TLS}"
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
