#!/usr/bin/env bash

export TEST_ACRA_PORT=6000
export TEST_PROXY_PORT=7000
export TEST_PROXY_COMMAND_PORT=8000
cd $HOME/project
for version in $VERSIONS; do
    echo "-------------------- Testing Go version $version"

    export TEST_ACRA_PORT=$(expr ${TEST_ACRA_PORT} + 1);
    export TEST_PROXY_PORT=$(expr ${TEST_PROXY_PORT} + 1);
    export TEST_PROXY_COMMAND_PORT=$(expr ${TEST_PROXY_COMMAND_PORT} + 1);
    export GOROOT=$HOME/go_root_$version/go;
    export PATH=$GOROOT/bin/:$PATH;
    export GOPATH=$HOME/go_path_$version;

    # setup postgresql credentials
    #export TEST_DB_USER=${POSTGRES_USER}
    #export TEST_DB_USER_PASSWORD=${POSTGRES_PASSWORD}
    #export TEST_DB_NAME=postgres
    export TEST_DB_PORT=5432
    unset TEST_MYSQL

    export TEST_TLS=on
    
    echo "--------------------  Testing POSTGRES with TEST_TLS=on"

    python3 tests/test.py -v;
    if [ "$?" != "0" ]; then echo "pgsql-$version" >> "$FILEPATH_ERROR_FLAG";
    fi

    export TEST_TLS=off

    echo "--------------------  Testing POSTGRES with TEST_TLS=off"
    python3 tests/test.py -v;
    if [ "$?" != "0" ]; then echo "pgsql-$version" >> "$FILEPATH_ERROR_FLAG";
    fi

    # setup mysql credentials
    #export TEST_DB_USER=${MYSQL_USER}
    #export TEST_DB_USER_PASSWORD=${MYSQL_PASSWORD}
    #export TEST_DB_NAME=${MYSQL_DATABASE}
    export TEST_DB_PORT=3306
    export TEST_MYSQL=true
    export TEST_TLS=off

    echo "--------------------  Testing TEST_MYSQL with TEST_TLS=off"
    python3 tests/test.py -v;
    if [ "$?" != "0" ]; then echo "mysql-$version" >> "$FILEPATH_ERROR_FLAG";
    fi

done
