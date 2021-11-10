#!/usr/bin/env bash

TEST_REDIS_HOST="${TEST_REDIS_HOST:-localhost}"
TEST_REDIS_PORT="${TEST_REDIS_PORT:-6379}"

NUM_PINGS="${NUM_PINGS:-15}"
DELAY="${DELAY:-1}"

for try in $(seq $NUM_PINGS); do
  curl -XGET "http://${TEST_REDIS_HOST}:${TEST_REDIS_PORT}/"

  # empty reply status
  if [ "$?" -eq "52" ]; then
    exit 0
  else
    sleep ${DELAY}
  fi
done

echo "Cannot reach the Redis at TEST_REDIS_HOST"
exit 1
