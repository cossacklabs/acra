#!/usr/bin/env bash

set -euo pipefail

genkeys_raise() {
    echo -e "\\nERROR: $*\\n" >&2
    exit 1
}

genkeys_help() {
echo "
Usage:
    generate-keys.sh [option] ...

    Please do not forget to pass master key via ACRA_MASTER_KEY environment
    variable.

Options:
    common options:
        --keys_dir <directory>
            Directory where the keys' structure will be created and the
            generated keys are placed (default './.acrakeys')
        --client_id
            Client id (default 'testclientid')
        --generate_acraserver_keys
            Create keypair for AcraServer only
        --generate_acraconnector_keys
            Create keypair for AcraConnector only
        --generate_acrawriter_keys
            Create keypair for data encryption/decryption only

Examples:
    generate-keys.sh
        Generate all keys and place them into ./.acrakeys directory structure.
    generate-keys.sh --keys_dir ./mykeysdir --client myclient
        Generate all keys and place them into ./mykeysdir directory structure,
        use client id 'myclient'.
    generate-keys.sh --generate_acraserver_keys --generate_acraconnector_keys
        Generate keys for AcraServer and AcraConnector.
"
}

genkeys_parse_args() {
    keys_dir="./.acrakeys"
    client_id="testclientid"
    flag_generate_server_keys=""
    flag_generate_connector_keys=""
    flag_generate_writer_keys=""
    while (( $# > 0 )); do
        arg="$1"
        shift
        case "$arg" in
            (--keys_dir)
                [[ -n "${1:-}" ]] || genkeys_raise \
                    "directory must be specified next to --keys_dir option."
                keys_dir="$1"
                shift
                ;;
            (--client_id)
                [[ -n "${1:-}" ]] || genkeys_raise \
                    "client identificator must be specified next to --client_id option."
                client_id="$1"
                shift
                ;;
            (--generate_acraserver_keys)
                flag_generate_server_keys="1"
                ;;
            (--generate_acraconnector_keys)
                flag_generate_connector_keys="1"
                ;;
            (--generate_acrawriter_keys)
                flag_generate_writer_keys="1"
                ;;
            (help|-help|--help|-h|--h|-?|--?)
                genkeys_help
                exit 0
                ;;
            (*)
                genkeys_help
                exit 3
                ;;
        esac
    done
    if [[ -z $flag_generate_server_keys && \
          -z $flag_generate_connector_keys && \
          -z $flag_generate_writer_keys ]]; then
        flag_generate_server_keys="1"
        flag_generate_connector_keys="1"
        flag_generate_writer_keys="1"
    fi
}

genkeys_check() {
    ACRA_KEYMAKER="acra-keymaker"
    if [[ -x "build/${ACRA_KEYMAKER}" ]]; then
        CMD="build/${ACRA_KEYMAKER}"
    elif [[ -x "${GOPATH}/bin/${ACRA_KEYMAKER}" ]]; then
        CMD="${GOPATH}/bin/${ACRA_KEYMAKER}"
    elif CMD=$(which $ACRA_KEYMAKER); then
        return
    else
        genkeys_raise "$ACRA_KEYMAKER was not found in any of the following "\
"paths: './build', '\$GOPATH/bin', '\$PATH'. Please do 'make install' to "\
"build and install Acra's components."
    fi
}

genkeys_generate() {
    local args="--client_id $client_id"
    mkdir -p "$keys_dir"
    if [[ -n $flag_generate_server_keys ]]; then
        mkdir -p "$keys_dir"/acra-{server,connector}
        chmod -R a-rwx,u+rwX "$keys_dir"
        $CMD $args --generate_acraserver_keys \
            --keys_output_dir=${keys_dir}/acra-server \
            --keys_public_output_dir=${keys_dir}/acra-connector
    fi
    if [[ -n $flag_generate_connector_keys ]]; then
        mkdir -p "$keys_dir"/acra-{server,connector}
        chmod -R a-rwx,u+rwX "$keys_dir"
        $CMD $args --generate_acraconnector_keys \
            --keys_output_dir=${keys_dir}/acra-connector \
            --keys_public_output_dir=${keys_dir}/acra-server
    fi
    if [[ -n $flag_generate_writer_keys ]]; then
        mkdir -p "$keys_dir"/acra-{server,writer}
        chmod -R a-rwx,u+rwX "$keys_dir"
        $CMD $args --generate_acrawriter_keys \
            --keys_output_dir=${keys_dir}/acra-server \
            --keys_public_output_dir=${keys_dir}/acra-writer
    fi
}

genkeys_main() {
    genkeys_parse_args "$@"
    genkeys_check
    genkeys_generate
}

genkeys_main "$@"
