#!/usr/bin/env bash

# run go fmt and count output lines
# gofmt print file names which was formatted and nothing if none was formatted
# count lines with wc and check that 0 lines was in output
result=$(go fmt ./... | wc -l)
if [[ $result != "0" ]]; then
  # something was formatted
  exit 1;
else
  exit 0;
fi;