FROM vault:1.6.2

COPY tests/ssl/vault/vault_crt.pem /data/vault-volume/vault_crt.pem
COPY tests/ssl/vault/vault_key.pem /data/vault-volume/vault_key.pem
COPY tests/ssl/ca/ca.crt /data/vault-volume/root.crt

RUN chown -R vault:vault /data/vault-volume
