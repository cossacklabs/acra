#!/usr/bin/env bash

TEST_VAULT_HOST="${TEST_VAULT_HOST:-localhost}"
TEST_VAULT_PORT="${TEST_VAULT_PORT:-8201}"

NUM_PINGS="${NUM_PINGS:-15}"
DELAY="${DELAY:-1}"

for try in $(seq $NUM_PINGS); do
  curl -XGET "https://${TEST_VAULT_HOST}:${TEST_VAULT_PORT}/"

    #60 code is SSL certificate problem - means that we can reach host
  if [ "$?" -eq "60" ]; then
    exit 0
  else
    sleep ${DELAY}
  fi
done

echo "Cannot reach the HashiCorp Vault at $TEST_VAULT_HOST"
exit 1
