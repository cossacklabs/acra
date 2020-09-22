#!/usr/bin/env bash

export PATH=$GOROOT/bin:$PATH

# run go fmt and count output lines
# gofmt print file names which was formatted and nothing if none was formatted
# count lines with wc and check that 0 lines was in output

# ignore sqlparser/sql.go because code may be generated with different go version than version that will check
# formatting and have different rules/conventions. we should not care about auto-generated code formatting
result=$(go fmt ./... | grep -v "sqlparser/sql.go" | wc -l)
if [[ $result -gt 0 ]]; then
  # something was formatted
  echo "Too many gofmt issues: $result"
  exit 1;
else
  echo "OK: don't have any gofmt issues"
  exit 0;
fi;