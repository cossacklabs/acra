#!/usr/bin/env bash
export TEST_ACRA_PORT=6000
export TEST_PROXY_PORT=7000
export TEST_PROXY_COMMAND_PORT=8000
cd $HOME/project
for version in $VERSIONS; do
export TEST_ACRA_PORT=$(expr ${TEST_ACRA_PORT} + 1);
export TEST_PROXY_PORT=$(expr ${TEST_PROXY_PORT} + 1);
export TEST_PROXY_COMMAND_PORT=$(expr ${TEST_PROXY_COMMAND_PORT} + 1);
export GOROOT=$HOME/go_root_$version/go;
export PATH=$GOROOT/bin/:$PATH;
export GOPATH=$HOME/go_path_$version;
strace -rfo /tmp/strace.out python3 tests/test.py;
if [ "$?" != "0" ]; then echo "$version" >> "$FILEPATH_ERROR_FLAG";
fi done