#!/usr/bin/env bash

# ignore protobuf-generated code, as well as yacc (.y) parser files
# duplicate output to stderr so we can see it in console while `wc` is counting the lines
result=$(ineffassign . | grep -v "\.pb\.go\|\.y" | tee /dev/stderr | wc -l)

if [[ $result -gt 1 ]]; then
  echo "Too many ineffassign issues: $result"
  exit 1;
else
  echo "OK: don't have too many ineffassign issues: $result"
  exit 0;
fi;
