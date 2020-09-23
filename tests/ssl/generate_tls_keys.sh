#!/usr/bin/env bash

# Common Name will be filled in later
subj="/C=GB/ST=London/L=London/O=Global Security/OU=IT"
EXPIRE=18250 # 50 years
OUT_DIR=tests/ssl

mkdir -p ${OUT_DIR}/ca
# Generate a new private key for CA and self-signed certificate.
# Use CA extensions from the configuration file and a different CN.
openssl req -x509 \
    -newkey rsa:2048 -nodes \
    -keyout ${OUT_DIR}/ca/ca.key \
    -out ${OUT_DIR}/ca/ca.crt \
    -sha256 \
    -subj "${subj}/CN=Test CA certificate" \
    -config "$(dirname $0)/openssl.cnf" -extensions "v3_ca" \
    -days ${EXPIRE}

declare -a names=("mysql" "postgresql" "acra-writer" "acra-server")
for name in "${names[@]}"
do
    mkdir -p "${OUT_DIR}/${name}"
    # create private key
    openssl genrsa -out "${OUT_DIR}/${name}/${name}.key" 2048
    # Generate certificate signing request for a service.
    # Certificate's CN must be different from the CA's CN.
    openssl req -new \
        -key "${OUT_DIR}/${name}/${name}.key" \
        -out "${OUT_DIR}/${name}/${name}.csr" \
        -subj "${subj}/CN=Test leaf certificate"
    # Sign certificate with CA private key, adding appropriate extensions.
    # The extensions issue certificate for "localhost" which validates locally
    # and avoids the need to patch /etc/hosts on the testing machines.
    openssl x509 -req \
        -in "${OUT_DIR}/${name}/${name}.csr" \
        -out "${OUT_DIR}/${name}/${name}.crt" \
        -sha256 \
        -CA "${OUT_DIR}/ca/ca.crt" -CAkey "${OUT_DIR}/ca/ca.key" -CAcreateserial \
        -extfile "$(dirname $0)/openssl.cnf" -extensions "v3_req" \
        -days ${EXPIRE}

    # remove .csr because doesn't need anymore
    rm "${OUT_DIR}/${name}/${name}.csr"
    # set correct rights for private key
    chmod 0400 "${OUT_DIR}/${name}/${name}.key"
done
# remove redundant file with serial numbers of signed certificates
rm ${OUT_DIR}/ca/ca.srl
