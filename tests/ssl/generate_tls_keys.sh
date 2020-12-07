#!/usr/bin/env bash

# Common Name will be filled in later
SUBJ="/C=GB/ST=London/L=London/O=Global Security/OU=IT"
EXPIRE=18250 # 50 years
OUT_DIR=tests/ssl
SKIP_EXISTING=${SKIP_EXISTING:-0} # set to 1 to avoid re-generation of existing certificates

mkdir -p ${OUT_DIR}/ca
# Generate a new private key for CA and self-signed certificate.
# Use CA extensions from the configuration file and a different CN.
[ "$SKIP_EXISTING" = 0 ] || [ ! -f "${OUT_DIR}/ca/ca.crt" ] && \
openssl req -x509 \
    -newkey rsa:2048 -nodes \
    -keyout ${OUT_DIR}/ca/ca.key \
    -out ${OUT_DIR}/ca/ca.crt \
    -sha256 \
    -subj "${subj}/CN=Test CA certificate" \
    -config "$(dirname $0)/openssl.cnf" -extensions "v3_ca" \
    -days ${EXPIRE}

# certificate database will be regenerated
rm -f ${OUT_DIR}/index.txt

declare -a names=("mysql" "postgresql" "acra-writer" "acra-writer-revoked" "acra-server" "ocsp-responder")
for name in "${names[@]}"
do
    subj="${SUBJ}/CN=Test leaf certificate ($name)"
    mkdir -p "${OUT_DIR}/${name}"
    # create private key
    [ "$SKIP_EXISTING" = 0 ] || [ ! -f "${OUT_DIR}/${name}/${name}.key" ] && \
    echo "==> Generating private key for ${name}" && \
    openssl genrsa -out "${OUT_DIR}/${name}/${name}.key" 2048

    # Generate certificate signing request for a service.
    # Certificate's CN must be different from the CA's CN.
    [ "$SKIP_EXISTING" = 0 ] || [ ! -f "${OUT_DIR}/${name}/${name}.crt" ] && \
    echo "==> Generating certificate request for ${name}" && \
    openssl req -new \
        -key "${OUT_DIR}/${name}/${name}.key" \
        -out "${OUT_DIR}/${name}/${name}.csr" \
        -subj "$subj"

    if [[ "$name" = *ocsp* ]]; then
        # use different configuration for OCSP responder
        extensions=v3_OCSP
    else
        # and different for usual certificates (see openssl.cnf)
        extensions=v3_req
    fi

    # Sign certificate with CA private key, adding appropriate extensions.
    # The extensions issue certificate for "localhost" which validates locally
    # and avoids the need to patch /etc/hosts on the testing machines.
    [ "$SKIP_EXISTING" = 0 ] || [ ! -f "${OUT_DIR}/${name}/${name}.crt" ] && \
    echo "==> Signing certificate for ${name}" && \
    openssl x509 -req \
        -in "${OUT_DIR}/${name}/${name}.csr" \
        -out "${OUT_DIR}/${name}/${name}.crt" \
        -sha256 \
        -CA "${OUT_DIR}/ca/ca.crt" -CAkey "${OUT_DIR}/ca/ca.key" -CAcreateserial \
        -extfile "$(dirname $0)/openssl.cnf" -extensions "$extensions" \
        -days ${EXPIRE}

    # remove .csr because doesn't need anymore
    rm -f "${OUT_DIR}/${name}/${name}.csr"
    # set correct rights for private key
    chmod 0400 "${OUT_DIR}/${name}/${name}.key"

    # Add recently created certificate to database (needed for OpenSSL OCSP server).
    # We could avoid crafting index.txt manually, but that requires regeneration of
    # all certificates and using `openssl ca` for signing .csr with CA key (so openssl
    # will automatically add all signed certs to database).
    serial="$(openssl x509 -in ${OUT_DIR}/${name}/${name}.crt -serial -noout | cut -d '=' -f 2)"
    enddate="$(openssl x509 -in ${OUT_DIR}/${name}/${name}.crt -enddate -noout | cut -d '=' -f 2)"
    enddate="$(date -d "$enddate" '+%y%m%d%H%M%SZ')"
    # https://pki-tutorial.readthedocs.io/en/latest/cadb.html
    echo -e "V\t$enddate\t\t${serial}\tunknown\t${subj}" >> ${OUT_DIR}/index.txt

    # certificates ending with "-revoked" should be revoked
    if [[ "$name" = *-revoked ]]; then
        echo "==> Revoking $name"
        openssl ca \
            -config "$(dirname $0)/openssl.cnf" \
            -revoke "${OUT_DIR}/${name}/${name}.crt"
    fi
done

# generate CRL (Certificate Revocation List)
openssl ca \
    -gencrl \
    -config "$(dirname $0)/openssl.cnf" \
    -crldays "${EXPIRE}" \
    -out "${OUT_DIR}/crl.pem"

# remove redundant file with serial numbers of signed certificates
rm -f ${OUT_DIR}/ca/ca.srl ${OUT_DIR}/*.old
