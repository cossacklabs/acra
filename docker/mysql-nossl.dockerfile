FROM mysql:5.7

RUN sed -i '/^\[mysqld\]/a skip_ssl' /etc/mysql/mysql.conf.d/mysqld.cnf
