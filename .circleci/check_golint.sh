#!/usr/bin/env bash

# run golint and count output lines
# golint print issues it found in source files
# count lines with wc and check that N lines was in output
result=$($GOPATH/bin/golint ./... | wc -l)
if [[ $result -gt 150 ]]; then
  # too many golint issues
  echo "Too many golint issues: $result"
  exit 1;
else
  echo "OK: don't have too many golint issues: $result"
  exit 0;
fi;
