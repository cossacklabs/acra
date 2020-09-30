#!/usr/bin/env bash
set -e

TEST_DB_HOST="${TEST_DB_HOST:-127.0.0.1}"
TEST_DB_USER="${TEST_DB_USER:-test}"
TEST_DB_NAME="${TEST_DB_NAME:-test}"

NUM_PINGS="${NUM_PINGS:-15}"
DELAY="${DELAY:-1}"

for try in $(seq $NUM_PINGS); do
    pg_isready \
        -h"$TEST_DB_HOST" \
        -U"$TEST_DB_USER" \
        -d"$TEST_DB_NAME" \
        && exit 0 || sleep $DELAY
done

echo "Cannot reach the database at $TEST_DB_HOST"
exit 1
