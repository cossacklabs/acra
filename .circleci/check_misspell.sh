#!/usr/bin/env bash

# ignore protobuf-generated code, just in case
# duplicate output to stderr so we can see it in console while `wc` is counting the lines
result=$($GOPATH/bin/misspell **/*.go **/*.py **/*.md | grep -v "\.pb\.go" | tee /dev/stderr | wc -l)

if [[ $result -gt 0 ]]; then
  echo "Too many misspell issues: $result"
  exit 1;
else
  echo "OK: don't have too many misspell issues: $result"
  exit 0;
fi;
