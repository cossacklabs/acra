#!/bin/bash

# Install latest Golang version on Linux
# See https://golang.org/dl/
#
# This script accepts next environment variables:
#     - GO_VERSIONS : go version list, such as "1.14.9 1.15.2"
#     - GO_TARBALL_CLEAN : 1 - clean up after install
#
# Also, it expects to find file with the same name, but ".csums" at the end rather than ".sh"
# this file should contain one Go version + SHA256 checksum combo per line, like this:
# 1.15.2 b49fda1ca29a1946d6bb2a5a6982cf07ccd2aba849289508ee0f9918f6bb4552
# this .csum file will then be used to check downloaded .tar.gz archives

set -euo pipefail

install_go() {
  # required vars: GO_PREFIX_DIR, GO_VERSION, GO_TARBALL_DIGEST
  # optional vars: GO_TARBALL_CLEAN
  GO_TARBALL="go${GO_VERSION}.linux-amd64.tar.gz"
  GO_URL="https://dl.google.com/go/$GO_TARBALL"
  GO_TARBALL_TMP_PATH="/tmp/$GO_TARBALL"
  GO_TARBALL_CLEAN="${GO_TARBALL_CLEAN:-0}"

  if [ ! -f "$GO_TARBALL_TMP_PATH" ]; then
    curl "$GO_URL" > "$GO_TARBALL_TMP_PATH"
  fi

  if [ "$(sha256sum "$GO_TARBALL_TMP_PATH" | awk '{print $1}')" != "$GO_TARBALL_DIGEST" ]; then
    echo "ERROR : checksum does not match" >&2
    exit 1
  fi

  tmpdir="$(mktemp -d /tmp/go-install.XXXXXX)"
  tar -C "$tmpdir" -xzf "$GO_TARBALL_TMP_PATH"
  mv "$tmpdir/go" "$GO_PREFIX_DIR"
  rm -r "$tmpdir"

  if [[ $GO_TARBALL_CLEAN == '1' ]]; then
    rm -f "$GO_TARBALL_TMP_PATH"
  fi

  PATH="$PATH:${GO_PREFIX_DIR}/bin" go version
}

THIS_FILE="$(realpath $0)"
CSUMS_FILE="${THIS_FILE/.sh/.csums}"

if [ ! -f "$CSUMS_FILE" ]; then
  echo "Error: $CSUMS_FILE does not exist" >&2
  exit 1
fi

GO_VERSIONS="${GO_VERSIONS:-1.19}"

for GO_VERSION in $GO_VERSIONS; do
  # gotta replace `.` -> `\.` for AWK regex so it will match exactly what we're asking for
  go_awk_version="${GO_VERSION//./\\.}"

  GO_TARBALL_DIGEST="$(awk "/^$go_awk_version / { print \$2 }" "$CSUMS_FILE")"
  if [ -z "$GO_TARBALL_DIGEST" ]; then
    echo "Error: no checksum for go $GO_VERSION was found in $CSUMS_FILE or the file is malformed" >&2
    exit 1
  fi

  mkdir -p /usr/local/lib/go
  GO_PREFIX_DIR="/usr/local/lib/go/$GO_VERSION"

  echo "Installing Go $GO_VERSION into $GO_PREFIX_DIR"
  install_go
done

latest_version="$(echo "$GO_VERSIONS" | tr ' ' '\n' | sort --version-sort --reverse | head -1)"

# symlink /usr/local/lib/go/latest -> /usr/local/lib/go/whatever_version_is_the_newest
ln -s "$latest_version" /usr/local/lib/go/latest
