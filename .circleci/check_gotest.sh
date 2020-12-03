#!/usr/bin/env bash

# Run test in each go environment and log errors to $FILEPATH_ERROR_FLAG.
# If all tests pass successfully then the file will not be created at all.
# cd to code with go.mod file outside of GOPATH to work with module-based behaviour
# https://github.com/golang/go/wiki/Modules#when-do-i-get-old-behavior-vs-new-module-based-behavior

# Re-generate CRL so it is up-to-date when used in tests
SKIP_EXISTING=1 ./tests/ssl/generate_tls_keys.sh

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

    echo "Using $(go version) at $(which go)"
    echo "GOROOT=$GOROOT"
    echo "PATH=$PATH"
    
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
