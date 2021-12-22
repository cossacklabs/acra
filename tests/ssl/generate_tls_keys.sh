#!/usr/bin/env bash

# Common Name will be filled in later
SUBJ="/C=GB/ST=London/L=London/O=Global Security/OU=IT"
EXPIRE=18250 # 50 years
OUT_DIR=tests/ssl
SKIP_EXISTING=${SKIP_EXISTING:-0} # set to 1 to avoid re-generation of existing certificates
TMPDIR="$(mktemp -d)"

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

gen_cert() {
    signer="$1"
    name="$2"

    case "$name" in
        *-ca)
            extensions=v3_intermediate_ca
            CN="Test CA certificate ($name)"
            ;;
        *ocsp*)
            extensions=v3_OCSP
            CN="Test leaf certificate ($name)"
            ;;
        *)
            extensions=v3_req
            CN="Test leaf certificate ($name)"
            ;;
    esac

    config="$(dirname $0)/openssl-$signer.cnf"

    [ -e "$OUT_DIR/$signer/index.txt" ] || touch "$OUT_DIR/$signer/index.txt"
    [ -e "$OUT_DIR/$signer/serial" ] || echo 01 > "$OUT_DIR/$signer/serial"

    subj="${SUBJ}/CN=$CN"
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

    # use service name as additional subjectAlternative name to use in docker-compose files and access via service names
    export SAN="${name}"

    # Sign certificate with CA private key, adding appropriate extensions.
    # The extensions issue certificate for "localhost" which validates locally
    # and avoids the need to patch /etc/hosts on the testing machines.
    [ "$SKIP_EXISTING" = 0 ] || [ ! -f "${OUT_DIR}/${name}/${name}.crt" ] && \
    echo "==> Signing certificate for ${name}" && \
    openssl ca \
        -config "$config" \
        -in "${OUT_DIR}/${name}/${name}.csr" \
        -out "${OUT_DIR}/${name}/${name}.crt" \
        -extensions "$extensions" \
        -batch \
        -outdir "$TMPDIR" \
        -rand_serial \
        -notext \
        -days "$EXPIRE"

    # remove .csr because doesn't need anymore
    rm -f "${OUT_DIR}/${name}/${name}.csr"
    # set correct rights for private key
    chmod 0400 "${OUT_DIR}/${name}/${name}.key"

    # certificates ending with "-revoked" should be revoked
    if [[ "$name" = *-revoked ]]; then
        echo "==> Revoking $name"
        openssl ca \
            -config "$config" \
            -revoke "${OUT_DIR}/${name}/${name}.crt"
    fi
}

gen_crl() {
    signer="$1"

    config="$(dirname $0)/openssl-$signer.cnf"

    # generate CRL (Certificate Revocation List) signed by corresponding CA
    openssl ca \
        -gencrl \
        -config "$config" \
        -crldays "${EXPIRE}" \
        -out "${OUT_DIR}/$signer/crl.pem"
}

declare -a names=("mysql" "postgresql" "acra-writer" "acra-writer-2" "acra-writer-revoked" "acra-server" "ocsp-responder" "intermediate-ca" "vault" 'acra-client')
for name in "${names[@]}"; do
    gen_cert ca $name

    if [[ "$name" = "vault" ]]; then
        openssl x509 -in "${OUT_DIR}/${name}/${name}.crt" -out "${OUT_DIR}/${name}/${name}_crt.pem" -outform PEM
        openssl rsa -in "${OUT_DIR}/${name}/${name}.key" -out "${OUT_DIR}/${name}/${name}_key.pem" -outform PEM
    fi

done
gen_crl ca

declare -a names=("intermediate-acra-writer" "intermediate-acra-writer-revoked" "intermediate-acra-server" "intermediate-ocsp-responder")
for name in "${names[@]}"; do
    gen_cert intermediate-ca $name
done
gen_crl intermediate-ca

# remove temporary dir and redundant files
rm -rf "$TMPDIR"
find "$OUT_DIR" -name '*.old' -delete

# To re-generate ca/crl_with_root.pem (used to test handling of self-revoked root cert), run from project root:
# 1) openssl ca -config tests/ssl/openssl-ca.cnf -revoke tests/ssl/ca/ca.crt
# 2) openssl ca -gencrl -config tests/ssl/openssl-ca.cnf -crldays 18250 -out tests/ssl/ca/crl_with_root.pem
# this will also add revoked root cert to ca/index.txt, so you'll have to revert the change with git
