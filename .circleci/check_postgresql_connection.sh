#!/usr/bin/env bash
set -e

POSTGRES_HOST="${POSTGRES_HOST:-127.0.0.1}"
POSTGRES_USER="${POSTGRES_USER:-test}"
POSTGRES_DB="${POSTGRES_DB:-test}"

NUM_PINGS="${NUM_PINGS:-15}"
DELAY="${DELAY:-1}"

for try in $(seq $NUM_PINGS); do
    pg_isready \
        -h"$POSTGRES_HOST" \
        -U"$POSTGRES_USER" \
        -d"$POSTGRES_DB" \
        && exit 0 || sleep $DELAY
done

echo "Cannot reach the database at $POSTGRES_HOST"
exit 1
