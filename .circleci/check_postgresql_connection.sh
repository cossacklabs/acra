#!/usr/bin/env bash

[ -n "$POSTGRES_USER" ] || POSTGRES_USER=test
[ -n "$POSTGRES_DB" ] || POSTGRES_DB=test

[ -n "$NUM_PINGS" ] || NUM_PINGS=15
[ -n "$DELAY" ] || DELAY=1

for try in $(seq $NUM_PINGS); do
    pg_isready -U"${POSTGRES_USER}" -d"${POSTGRES_DB}" -h127.0.0.1 && exit 0 || sleep $DELAY
done

echo "Cannot reach the database"
exit 1
