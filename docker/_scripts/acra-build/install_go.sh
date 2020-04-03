#!/bin/bash

# Install latest Golang version on Linux
# See https://golang.org/dl/
#
# This script accepts next environment variables:
#     - GO_VERSION : go version "1.12.4"
#     - GO_TARBALL_DIGEST : sha256 hash
#     - GO_PREFIX_DIR : directory prefix to install go
#     - GO_TARBALL_CLEAN : 1 - clean up after install

set -euo pipefail

GO_PREFIX_DIR="${GO_PREFIX_DIR:-$HOME}"
GO_VERSION="${GO_VERSION:-1.13.9}"
GO_TARBALL_DIGEST="${GO_TARBALL_DIGEST:-f4ad8180dd0aaf7d7cda7e2b0a2bf27e84131320896d376549a7d849ecf237d7}"
GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://dl.google.com/go/$GO_TARBALL"
GO_TARBALL_TMP_PATH="/tmp/$GO_TARBALL"
GO_TARBALL_CLEAN="${GO_TARBALL_CLEAN:-0}"

if [ ! -f "$GO_TARBALL_TMP_PATH" ]; then
    curl "$GO_URL" > "$GO_TARBALL_TMP_PATH"
fi
if [ "$(sha256sum "$GO_TARBALL_TMP_PATH" | awk '{print $1}')" != "$GO_TARBALL_DIGEST" ]; then
    echo 2>&1 "ERROR : checksum does not match"
    exit 1
fi

tar -C "$GO_PREFIX_DIR" -xzf "$GO_TARBALL_TMP_PATH"
if [[ $GO_TARBALL_CLEAN == '1' ]]; then
    rm -f "$GO_TARBALL_TMP_PATH"
fi

export PATH="$PATH:${GO_PREFIX_DIR}/go/bin"
go version
