#!/usr/bin/env bash
export ACRA_CLIENT_ID="test"
export ACRA_CONNECTOR_PORT=9494
export ACRA_CONNECTOR_HOST=127.0.0.1
export DB_PORT=5432
# in our example database will running on the same host
export DB_HOST=127.0.0.1

export EXAMPLE_ACRA_CONNECTOR_API_ADDRESS=http://${ACRA_CONNECTOR_HOST}:${ACRA_CONNECTOR_PORT}
export EXAMPLE_HOST=127.0.0.1
export EXAMPLE_PORT=9494
export EXAMPLE_DB_USER=test
export EXAMPLE_DB_PASSWORD=test
export EXAMPLE_DB_NAME=test
export EXAMPLE_PUBLIC_KEY=docker/.acrakeys/acra-writer/${ACRA_CLIENT_ID}_storage.pub
# for mysql use EXAMPLE_MYSQL=true
export EXAMPLE_POSTGRESQL=true