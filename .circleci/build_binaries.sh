#!/usr/bin/env bash
set -o pipefail

OLD_PATH="$PATH"

if [ -z "$GO_VERSIONS" ]; then
    # extract default Go version from $GOROOT
    GO_VERSIONS="$(readlink $GOROOT)"
fi
OUTPUT_FOLDER=${OUTPUT_FOLDER:-/tmp/acra-binaries}
mkdir -p "${OUTPUT_FOLDER}"
echo "${OUTPUT_FOLDER}"

for go_version in $GO_VERSIONS; do
    #export GOROOT="/usr/local/lib/go/$go_version"
    export GOROOT="/home/lagovas/.local/share/go${go_version}"

    if [ ! -d $GOROOT ]; then
        echo "Error: Go $go_version is not installed, $GOROOT does not exist"
        exit 1
    fi

    export PATH="$GOROOT/bin:$OLD_PATH"

    echo "-------------------- Testing $(go version) at $(which go)"
    echo "GOROOT=$GOROOT"
    echo "PATH=$PATH"
    mkdir -p "${OUTPUT_FOLDER}/${go_version}"
    binaries=$(find ./cmd -mindepth 1 -maxdepth 1 -type d)

    for binary_path in ${binaries}; do
      binary_name=$(basename "${binary_path}")
      echo "build ${binary_name}"
      go build -tags "${TEST_BUILD_TAGS}" -o "${OUTPUT_FOLDER}/${go_version}/${binary_name}" ${binary_path};
    done
done