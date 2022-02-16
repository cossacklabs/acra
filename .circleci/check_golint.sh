#!/usr/bin/env bash

# run golint and count output lines
# golint print issues it found in source files
# count lines with wc and check that N lines was in output
# skip linter issues for files generated by protobuf compiler because generation out of our control
# and skip issues about `_` in packages' names since we won't rename packages just to make this issue disappear
result=$(golint ./... | grep -v "\.pb\.go\|don't use an underscore in package name" | tee /dev/stderr | wc -l)

if [[ $result -gt 6 ]]; then
  # too many golint issues
  echo "Too many golint issues: $result"
  exit 1;
else
  echo "OK: don't have too many golint issues: $result"
  exit 0;
fi;
