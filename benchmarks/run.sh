#!/usr/bin/env bash
declare -a read_without_zone_scripts=("read/direct/direct.go" "read/onekey_without_acrastruct/onekey_without_acrastruct.go" "read/onekey_acrastruct/onekey_acrastruct.go")
declare -a read_with_zone_scripts=("read/zone_without_acrastruct/zone_without_acrastruct.go" "read/zone_acrastruct/zone_acrastruct.go")
declare -a write_scripts=("write/raw/raw.go" "write/withzone/withzone.go" "write/withoutzone/withoutzone.go")

#echo "run write scripts"
#for i in "${write_scripts[@]}"
#do
#   script="go run src/github.com/cossacklabs/acra/benchmarks/cmd/$i"
#   echo "run '$script'"
#   eval $script
#done


echo "run read scripts without zones"
for i in "${read_without_zone_scripts[@]}"
do
   script="go run src/github.com/cossacklabs/acra/benchmarks/cmd/$i"
   echo "run '$script'"
   eval $script
done

echo "run acraserver in zonemode and press ENTER"
read -e

echo "run read scripts with zones"
for i in "${read_with_zone_scripts[@]}"
do
   script="go run src/github.com/cossacklabs/acra/benchmarks/cmd/$i"
   echo "run '$script'"
   eval $script
done