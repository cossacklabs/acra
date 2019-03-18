#!/usr/bin/env bash

# Run test in each go environment and log errors to $FILEPATH_ERROR_FLAG.
# If all tests pass successfully then the file will not be created at all.
export GOPATH=$HOME/$GOPATH_FOLDER;
# cd to code with go.mod file outside of GOPATH to work with module-based behaviour
# https://github.com/golang/go/wiki/Modules#when-do-i-get-old-behavior-vs-new-module-based-behavior
cd $HOME/project

for version in $VERSIONS; do
    export GOROOT=$HOME/go_root_$version/go;
    export PATH=$GOROOT/bin/:$PATH;
    go test -v ./...;
    status="$?"
    if [[ "${status}" != "0" ]]; then
        echo "$version-tls12" >> "$FILEPATH_ERROR_FLAG";
    fi

    # test with supported tls1.3
    GODEBUG="tls13=1" go test -v github.com/cossacklabs/acra/...;
    status="$?"
    if [[ "${status}" != "0" ]]; then
        echo "$version-tls13" >> "$FILEPATH_ERROR_FLAG";
    fi
done

# if file exists (exit code of stat == 0 ) then something was wrong. cat file with versions of environments where was error and return exit 1
if [[ -f  $FILEPATH_ERROR_FLAG ]]; then
    cat "$FILEPATH_ERROR_FLAG";
    rm "$FILEPATH_ERROR_FLAG";
    exit 1;
fi