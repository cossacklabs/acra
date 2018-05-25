FROM mysql:5.7

# Original mysql init script expects empty /var/lib/mysql so we initially place
# certificates into the image to the intermediate directory
COPY docker/ssl/mysql/mysql.crt /tmp.ssl/server-cert.pem
COPY docker/ssl/mysql/mysql.key /tmp.ssl/server-key.pem
COPY docker/ssl/ca/example.cossacklabs.com.CA.crt /tmp.ssl/ca.pem
RUN chown -R mysql:mysql /tmp.ssl

COPY docker/mysql-ssl-configure.sh /docker-entrypoint-initdb.d/
