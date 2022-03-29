#!/usr/bin/env bash

# Run test in each go environment and log errors to $FILEPATH_ERROR_FLAG.
# If all tests pass successfully then the file will not be created at all.
# cd to code with go.mod file outside of GOPATH to work with module-based behaviour
# https://github.com/golang/go/wiki/Modules#when-do-i-get-old-behavior-vs-new-module-based-behavior

OLD_PATH="$PATH"
TEST_BUILD_TAGS=${TEST_BUILD_TAGS:-}
TEST_EXTRA_BUILD_FLAGS=${TEST_EXTRA_BUILD_FLAGS:-}

if [ -z "$GO_VERSIONS" ]; then
    # extract default Go version from $GOROOT
    GO_VERSIONS="$(readlink $GOROOT)"
fi

# for local run
if [ -z "$GO_VERSIONS" ]; then
  echo 'Run tests with local golang executable'
  go test -tags="${TEST_BUILD_TAGS}" ${TEST_EXTRA_BUILD_FLAGS} ./...;
  status="$?"
  exit $status
fi

# for circleci run
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
    
    go test -tags="${TEST_BUILD_TAGS}" ${TEST_EXTRA_BUILD_FLAGS} ./...;
    status="$?"
    if [[ "${status}" != "0" ]]; then
        echo "$version" >> "$FILEPATH_ERROR_FLAG";
    fi
done

# if file exists (exit code of stat == 0 ) then something was wrong. cat file with versions of environments where was error and return exit 1
if [[ -f  $FILEPATH_ERROR_FLAG ]]; then
    cat "$FILEPATH_ERROR_FLAG";
    rm "$FILEPATH_ERROR_FLAG";
    exit 1;
fi
