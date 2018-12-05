#!/usr/bin/env bash

# run go fmt and count output lines
# gofmt print file names which was formatted and nothing if none was formatted
# count lines with wc and check that 0 lines was in output
result=$(go fmt ./... | grep -v "sqlparser/sql.go" | wc -l)
if [[ $result -gt 0 ]]; then
  # something was formatted
  echo "Too many gofmt issues: $result"
  exit 1;
else
  echo "OK: don't have any gofmt issues"
  exit 0;
fi;