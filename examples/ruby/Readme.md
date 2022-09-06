See a verbose explanation of how to prepare environment and use the examples in [https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker/](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker/). The explanation is provided for Python, some minor tweaks might be needed to get Acra examples run with Ruby.

For example we will use next environment:
```
export ACRA_CLIENT_ID="test"
export DB_NAME="acra"
export DB_USER="dbuser"
export DB_PASSWORD="dbpassword"
export DB_HOST=127.0.0.1
export DB_PORT=5432
export ACRA_CONNECTOR_HOST=127.0.0.1
export ACRA_CONNECTOR_PORT=9494
```

# General
Scripts have next required params:
* `db_name`
* `db_user`
* `db_password`
* `host` (of database)
* `port` (of database)
* `postgresql` or `mysql` (depends on database you use)

Other params depends on  type of action (`print` to list rows from db or `data` to add encrypted data to database)

**Important**

If you use MySQL database then you should pass `--mysql` parameter in each example or `--postgresql` (used as default and may be omitted) if you use PostgreSQL as database

## Printing decrypted data
To see decrypted data you must use port of AcraConnector (default 9494). If you will print using databases port then you will see encrypted data

## Insert data
```
ruby examples/ruby/example.rb --db_name=${DB_NAME} --db_user=${DB_USER} --host=${DB_HOST} --port=${DB_PORT} --public_key=docker/.acrakeys/acra-writer/${ACRA_CLIENT_ID}_storage.pub --postgresql --data="some data"
```
## Print data

```
ruby examples/ruby/example.rb --db_name=${DB_NAME} --db_user=${DB_USER} --host=${ACRA_CONNECTOR_HOST} --port=${ACRA_CONNECTOR_PORT} --public_key=docker/.acrakeys/acra-writer/${ACRA_CLIENT_ID}_storage.pub --postgresql --print
```
*Use AcraServer's port:host to see encrypted data and databases host:port to see encrypted data*