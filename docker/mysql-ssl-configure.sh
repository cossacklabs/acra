#!/bin/bash

set -euo pipefail

MYSQL_DATA="/var/lib/mysql"

for f in ca.pem server-cert.pem server-key.pem; do
    cp /tmp.ssl/${f} "${MYSQL_DATA}/"
    chown mysql:mysql "${MYSQL_DATA}/${f}"
    chmod 0600 "${MYSQL_DATA}/${f}"
done
