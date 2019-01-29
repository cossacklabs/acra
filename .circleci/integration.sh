#!/usr/bin/env bash

export TEST_ACRASERVER_PORT=6000
export TEST_CONNECTOR_PORT=7000
export TEST_CONNECTOR_COMMAND_PORT=8000
export TEST_DB_USER=test
export TEST_DB_USER_PASSWORD=test
export TEST_DB_NAME=test

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
    export GOPATH=$HOME/$GOPATH_FOLDER;

    
    echo "--------------------  Testing with TEST_TLS=${TEST_TLS}"

    python3 tests/test.py -v;
    if [ "$?" != "0" ]; then echo "golang-$version test_tls=${TEST_TLS}" >> "$FILEPATH_ERROR_FLAG";
    fi

done
