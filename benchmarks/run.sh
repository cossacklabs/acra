#!/usr/bin/env bash
export ACRA_CONNECTION_STRING='dbname=benchmark user=test password=test host=127.0.0.1 port=9393'
export PG_CONNECTION_STRING='dbname=benchmark user=test password=test host=127.0.0.1 port=5432'

declare -a read_scripts=("read/direct/direct.go" "read/onekey_without_acrastruct/onekey_without_acrastruct.go" "read/onekey_acrastruct/onekey_acrastruct.go")
declare -a write_scripts=("write/raw/raw.go" "write/acrastruct/acrastruct.go")

echo "run write scripts"
for i in "${write_scripts[@]}"
do
   script="go run ./benchmarks/cmd/$i"
   echo "run '$script'"
   eval $script
done


echo "run read scripts"
for i in "${read_scripts[@]}"
do
   script="go run ./benchmarks/cmd/$i"
   echo "run '$script'"
   eval $script
done
