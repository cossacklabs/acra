#!/usr/bin/env bash

subj="/C=GB/ST=London/L=London/O=Global Security/OU=IT" # without CN value: /CN=localhost
EXPIRE=18250 # 50 years
OUT_DIR=tests/ssl

mkdir -p ${OUT_DIR}/ca
# create private key for ca and self-signed certificate
# CN value must be differ from client's CN (can't use localhost too) because certificate validation will be failed
openssl req -x509 -newkey rsa:2048 -sha256 -nodes -keyout ${OUT_DIR}/ca/ca.key -out ${OUT_DIR}/ca/ca.crt -days ${EXPIRE} -subj "${subj}/CN=ca-localhost"

declare -a names=("mysql" "postgresql" "acra-writer" "acra-server")
for name in "${names[@]}"
do
    mkdir -p "${OUT_DIR}/${name}"
    # create private key
    openssl genrsa -out "${OUT_DIR}/${name}/${name}.key" 2048
    # create certificate signing request with CN=localhost for correct validation locally running databases and avoid
    # patching /etc/hosts on local machines
    openssl req -new -key "${OUT_DIR}/${name}/${name}.key" -out "${OUT_DIR}/${name}/${name}.csr" -subj "${subj}/CN=localhost"
    # sign certificate with CA private key
    openssl x509 -req -in "${OUT_DIR}/${name}/${name}.csr" -CA "${OUT_DIR}/ca/ca.crt" -CAkey "${OUT_DIR}/ca/ca.key" -CAcreateserial -out "${OUT_DIR}/${name}/${name}.crt" -days ${EXPIRE} -sha256

    # remove .csr because doesn't need anymore
    rm "${OUT_DIR}/${name}/${name}.csr"
    # set correct rights for private key
    chmod 0400 "${OUT_DIR}/${name}/${name}.key"
done
# remove redundant file with serial numbers of signed certificates
rm ${OUT_DIR}/ca/ca.srl

