#!/usr/bin/env bash
export TEST_ACRA_PORT=6000
export TEST_PROXY_PORT=7000
export TEST_PROXY_COMMAND_PORT=8000
cd /home/lagovas/development/GOPATH/src/github.com/cossacklabs/acra
for version in $VERSIONS; do
export TEST_ACRA_PORT=$(expr ${TEST_ACRA_PORT} + 1);
export TEST_PROXY_PORT=$(expr ${TEST_PROXY_PORT} + 1);
export TEST_PROXY_COMMAND_PORT=$(expr ${TEST_PROXY_COMMAND_PORT} + 1);
export GOROOT=$HOME/golang/go_root_$version/go;
export PATH=$GOROOT/bin/:$PATH;
export GOPATH=$HOME/golang/go_path_$version;
python3 tests/test.py;
if [ "$?" != "0" ]; then echo "$version" >> "$FILEPATH_ERROR_FLAG";
fi done
