FROM postgres:9.6

# Original postgresql init script expects empty $PGDATA so we initially place
# certificates into the image to the intermediate directory
COPY docker/ssl/postgresql/postgresql.crt /tmp.ssl/server.crt
COPY docker/ssl/postgresql/postgresql.key /tmp.ssl/server.key
COPY docker/ssl/ca/example.cossacklabs.com.CA.crt /tmp.ssl/root.crt

COPY docker/postgresql-ssl-configure.sh /docker-entrypoint-initdb.d/
