FROM consul:1.13

COPY tests/ssl/consul/consul_crt.pem /data/consul-volume/dc1-server-consul-0.pem
COPY tests/ssl/consul/consul_key.pem /data/consul-volume/dc1-server-consul-0-key.pem
COPY tests/ssl/ca/ca.crt /data/consul-volume/root.crt

RUN chown -R consul:consul /data/consul-volume
