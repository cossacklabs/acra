#!/usr/bin/env bash
# need at least 1 arg of new dependency path
git apply patches/postgresql.patch
goyacc -o sql.go sql.y
scripts/change_dependency_name.sh "$@"
go test ./...
