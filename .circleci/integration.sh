#!/usr/bin/env bash

export TEST_ACRASERVER_PORT=6000
export TEST_CONNECTOR_PORT=7000
export TEST_CONNECTOR_COMMAND_PORT=8000
export TEST_DB_USER=test
export TEST_DB_USER_PASSWORD=test
export TEST_DB_NAME=test

cd $HOME/project
for version in $VERSIONS; do
    echo "-------------------- Testing Go version $version"

    export TEST_ACRASERVER_PORT=$(expr ${TEST_ACRASERVER_PORT} + 1);
    export TEST_CONNECTOR_PORT=$(expr ${TEST_CONNECTOR_PORT} + 1);
    export TEST_CONNECTOR_COMMAND_PORT=$(expr ${TEST_CONNECTOR_COMMAND_PORT} + 1);
    export GOROOT=$HOME/go_root_$version/go;
    export PATH=$GOROOT/bin/:$PATH;
    export GOPATH=$HOME/$GOPATH_FOLDER;

    export TEST_TLS=on
    
    echo "--------------------  Testing with TEST_TLS=on"

    strace -x -y -ff -o ${STRACE_OUT}/"golang-$version-${TEST_TLS}.strace" python3 tests/test.py -v;
    if [ "$?" != "0" ]; then echo "golang-$version" >> "$FILEPATH_ERROR_FLAG";
    fi

    export TEST_TLS=off

    echo "--------------------  Testing with TEST_TLS=off"
    strace -x -y -ff -o ${STRACE_OUT}/"golang-$version-${TEST_TLS}.strace" python3 tests/test.py -v;
    if [ "$?" != "0" ]; then echo "golang-$version" >> "$FILEPATH_ERROR_FLAG";
    fi
done
