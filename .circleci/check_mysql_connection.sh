#!/usr/bin/env bash
set -e

MYSQL_HOST="${MYSQL_HOST:-127.0.0.1}"
MYSQL_USER="${MYSQL_USER:-test}"
MYSQL_PASSWORD="${MYSQL_PASSWORD:-test}"

NUM_PINGS="${NUM_PINGS:-15}"
DELAY="${DELAY:-1}"

for try in $(seq $NUM_PINGS); do
    mysqladmin ping \
        -h"$MYSQL_HOST" \
        -u"$MYSQL_USER" \
        -p"$MYSQL_PASSWORD" \
        --protocol=TCP \
        && exit 0 || sleep $DELAY
done

echo "Cannot reach the database at $MYSQL_HOST"
exit 1
