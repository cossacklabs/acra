#!/usr/bin/env bash
set -e

export OUTPUT_DIR=${OUTPUT_DIR:-/tmp}
export BENCHMARK_NAME=${BENCHMARK_NAME:-default}
export ACRA_CONNECTION_STRING='dbname=benchmark user=test password=test host=localhost port=9393 sslmode=require sslkey=./docker/ssl/acra-client/acra-client.key sslcert=./docker/ssl/acra-client/acra-client.crt sslrootcert=./docker/ssl/ca/example.cossacklabs.com.crt'
export DIRECT_CONNECTION_STRING='dbname=benchmark user=test password=test host=localhost port=5432 sslmode=require sslkey=./docker/ssl/acra-client/acra-client.key sslcert=./docker/ssl/acra-client/acra-client.crt sslrootcert=./docker/ssl/ca/example.cossacklabs.com.crt'
export READ_TIMEOUT=${READ_TIMEOUT:-25}
export WRITE_TIMEOUT=${WRITE_TIMEOUT:-25}


go build -o read.bin ./benchmarks/cmd/read/direct/direct.go
go build -o write.bin ./benchmarks/cmd/write/raw/raw.go

echo "run write scripts"
# direct to database
export PG_CONNECTION_STRING=${DIRECT_CONNECTION_STRING}
script="./write.bin 2> >(tee -a ${BENCHMARK_NAME}.direct.txt)"
echo "run direct write '$script'"
eval $script

# run fetching profiling data
curl --silent -o "${OUTPUT_DIR}/${BENCHMARK_NAME}.write.pb.gz" "http://localhost:6060/debug/pprof/profile?seconds=${WRITE_TIMEOUT}" &
pid=$!

export PG_CONNECTION_STRING=${ACRA_CONNECTION_STRING}
script="./write.bin 2> >(tee -a ${BENCHMARK_NAME}.acra.txt)"
echo "run acra write '$script'"
eval $script
echo "wait $pid"
wait ${pid}


echo "run read scripts without zones"
export PG_CONNECTION_STRING=${DIRECT_CONNECTION_STRING}
script="./read.bin 2> >(tee -a ${BENCHMARK_NAME}.direct.txt)"
echo "run direct read '$script'"
eval $script

curl --silent -o "${OUTPUT_DIR}/${BENCHMARK_NAME}.read.pb.gz" "http://localhost:6060/debug/pprof/profile?seconds=${READ_TIMEOUT}" &
pid="$!"

export PG_CONNECTION_STRING=${ACRA_CONNECTION_STRING}
script="./read.bin 2> >(tee -a ${BENCHMARK_NAME}.acra.txt)"
echo "run acra read '$script'"
eval $script

echo "wait $pid"
wait ${pid}