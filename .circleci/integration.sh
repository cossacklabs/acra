#!/usr/bin/env bash

export TEST_ACRASERVER_PORT=6000
export TEST_CONNECTOR_PORT=7000
export TEST_CONNECTOR_COMMAND_PORT=8000
export TEST_DB_USER=test
export TEST_DB_USER_PASSWORD=test
export TEST_DB_NAME=test

declare -a tls_modes=("on" "off")

cd $HOME/project
for version in $VERSIONS; do
    echo "-------------------- Testing Go version $version"

    export TEST_ACRASERVER_PORT=$(expr ${TEST_ACRASERVER_PORT} + 1);
    export TEST_CONNECTOR_PORT=$(expr ${TEST_CONNECTOR_PORT} + 1);
    export TEST_CONNECTOR_COMMAND_PORT=$(expr ${TEST_CONNECTOR_COMMAND_PORT} + 1);
    export GOROOT=$HOME/go_root_$version/go;
    export PATH=$GOROOT/bin/:$PATH;
    export GOPATH=$HOME/$GOPATH_FOLDER;

    for tls_mode in "${tls_modes[@]}"
    do

        export TEST_TLS="${tls_mode}"

        echo "--------------------  Testing with TEST_TLS=${tls_mode}"

        # use nohup to ignore unknown sighup signals from test environment (detected on circleci)
        nohup python3 tests/test.py -v > logs.txt;
        if [[ "$?" != "0" ]]; then
            echo "golang-$version-${tls_mode}" >> "$FILEPATH_ERROR_FLAG";
        else
            echo "no errors";
        fi
        cat logs.txt;
        rm logs.txt;
    done
done
