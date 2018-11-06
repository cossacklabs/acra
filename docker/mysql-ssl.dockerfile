FROM mariadb:10.3

# Original init script expects empty /var/lib/mysql so we initially place
# certificates to the intermediate directory
COPY docker/ssl/mysql/mysql.crt /tmp.ssl/
COPY docker/ssl/mysql/mysql.key /tmp.ssl/
COPY docker/ssl/ca/example.cossacklabs.com.crt /tmp.ssl/ca.crt
RUN chown -R mysql:mysql /tmp.ssl

COPY docker/_scripts/mysql/mariadb-ssl.cnf /etc/mysql/mariadb.conf.d/
