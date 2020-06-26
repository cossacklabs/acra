#!/usr/bin/env bash

set -euo pipefail

APP_CURR_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
APP_SSL_MODE="${APP_SSL_MODE:-disable}"

chmod 0600 ${APP_CURR_DIR}/ssl/acra-writer/acra-writer.key

app_raise() {
    echo -e "\\nERROR: $*\\n" >&2
    exit 1
}

app_mysql_exec() {
    local command="$1"
    local port="${2:-3306}"
    local ssl="${3:-disable}"

    if [ "$ssl" == "enable" ]; then
        mysql -h 127.0.0.1 -u ${MYSQL_USER:-test} -p -P ${port} -D ${MYSQL_DATABASE:-test} \
            --password="${MYSQL_PASSWORD:-test}" \
            --ssl-cert="${APP_CURR_DIR}/ssl/acra-writer/acra-writer.crt" \
            --ssl-key="${APP_CURR_DIR}/ssl/acra-writer/acra-writer.key" \
            --ssl \
            --execute "${command}"
    else
        mysql -h 127.0.0.1 -u ${MYSQL_USER:-test} -p -P ${port} -D ${MYSQL_DATABASE:-test} \
            --password="${MYSQL_PASSWORD:-test}" \
            --execute "${command}"
    fi
}

app_pgsql_exec() {
    local command="$1"
    local port="${2:-5432}"
    local ssl="${3:-disable}"

    if [ "$ssl" == "enable" ]; then
        export PGSSLCERT="${APP_CURR_DIR}/ssl/acra-writer/acra-writer.crt"
        export PGSSLKEY="${APP_CURR_DIR}/ssl/acra-writer/acra-writer.key"
    fi

    psql "postgresql://${POSTGRES_USER:-test}:${POSTGRES_PASSWORD:-test}@127.0.0.1:${port}/${POSTGRES_DB:-test}" \
        -c "${command}"
}

app_mysql_write() {
    echo "Creating table"
    app_mysql_exec "CREATE TABLE IF NOT EXISTS test (id int, data blob);" "9494" "${APP_SSL_MODE}"
    echo "Writing data..."
    app_mysql_exec "INSERT INTO test VALUES (1, '00000');" "9494" "${APP_SSL_MODE}"
    app_mysql_exec "INSERT INTO test VALUES (2, '11111');" "9494" "${APP_SSL_MODE}"
}

app_pgsql_write() {
    echo "Creating table"
    app_pgsql_exec "CREATE TABLE IF NOT EXISTS test (id int, data text);" "9494" "${APP_SSL_MODE}"
    echo "Writing data..."
    app_pgsql_exec "INSERT INTO test VALUES (1, '00000');" "9494" "${APP_SSL_MODE}"
    app_pgsql_exec "INSERT INTO test VALUES (2, '11111');" "9494" "${APP_SSL_MODE}"
}

app_init() {
    local mode="$1"

    if [ "$mode" == "mysql" ]; then
        echo "Running in mysql mode"
        app_mysql_write
        echo "Reading data..."
        app_mysql_exec "select * from test;"
    elif [ "$mode" == "pgsql" ]; then
        echo "Running in mysql mode"
        app_pgsql_write
        echo "Reading data..."
        app_pgsql_exec "select * from test;"
    else
        app_raise "Unknown database $mode"
    fi
}

app_init "$1"
