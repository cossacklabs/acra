#!/usr/bin/env bash

[ -n "$MYSQL_USER" ] || MYSQL_USER=test
[ -n "$MYSQL_PASSWORD" ] || MYSQL_PASSWORD=test

[ -n "$NUM_PINGS" ] || NUM_PINGS=15
[ -n "$DELAY" ] || DELAY=1

for try in $(seq $NUM_PINGS); do
    mysqladmin ping -h127.0.0.1 -u"${MYSQL_USER}" -p"${MYSQL_PASSWORD}" --protocol=TCP && exit 0 || sleep $DELAY
done

echo "Cannot reach the database"
exit 1
