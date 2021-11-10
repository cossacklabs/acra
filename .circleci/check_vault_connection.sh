#!/usr/bin/env bash

TEST_VAULT_HOST="${TEST_VAULT_HOST:-localhost}"
TEST_VAULT_PORT="${TEST_VAULT_PORT:-8201}"

NUM_PINGS="${NUM_PINGS:-15}"
DELAY="${DELAY:-1}"

for try in $(seq $NUM_PINGS); do
  curl --cert 'tests/ssl/acra-writer/acra-writer.crt' \
    --key 'tests/ssl/acra-writer/acra-writer.key' \
    --cacert 'tests/ssl/ca/ca.crt' \
    -XGET "https://${TEST_VAULT_HOST}:${TEST_VAULT_PORT}/"

  if [ "$?" -eq "0" ]; then
    exit 0
  else
    sleep ${DELAY}
  fi
done

echo "Cannot reach the HashiCorp Vault at $TEST_TEST_VAULT_HOST"
exit 1
