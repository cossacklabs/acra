#!/usr/bin/env bash
set -e

TEST_DB_HOST="${TEST_DB_HOST:-127.0.0.1}"
TEST_DB_USER="${TEST_DB_USER:-test}"
TEST_DB_USER_PASSWORD="${TEST_DB_USER_PASSWORD:-test}"

NUM_PINGS="${NUM_PINGS:-15}"
DELAY="${DELAY:-1}"

for try in $(seq $NUM_PINGS); do
    mysqladmin ping \
        -h"$TEST_DB_HOST" \
        -u"$TEST_DB_USER" \
        -p"$TEST_DB_USER_PASSWORD" \
        --protocol=TCP \
        && exit 0 || sleep $DELAY
done

echo "Cannot reach the database at $TEST_DB_HOST"
exit 1
