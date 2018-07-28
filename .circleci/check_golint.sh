#!/usr/bin/env bash

# run golint and count output lines
# golint print issues it found in source files
# count lines with wc and check that 0 lines was in output
result=$(golint ./... | wc -l)
if [[ $result -gt 450 ]]; then
  # too many golint issues
  echo "Too many golint issues: $result"
  exit 1;
else
  echo "OK: don't have too many golint issues: $result"
  exit 0;
fi;