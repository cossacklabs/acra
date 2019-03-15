FROM postgres:11

# Original postgresql init script expects empty $PGDATA so we initially place
# certificates into the image to the intermediate directory
COPY tests/ssl/postgresql/postgresql.crt /tmp.ssl/server.crt
COPY tests/ssl/postgresql/postgresql.key /tmp.ssl/server.key
COPY tests/ssl/ca/ca.crt /tmp.ssl/root.crt
RUN chown -R postgres:postgres /tmp.ssl

COPY docker/_scripts/postgresql-ssl-configure.sh /docker-entrypoint-initdb.d/
