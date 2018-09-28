See a verbose explanation of how to prepare environment and use the examples in https://docs.cossacklabs.com/pages/trying-acra-with-docker/
For example we will use next environment:
```
export ACRA_CLIENT_ID="test"
export ACRA_CONNECTOR_PORT=9494
export ACRA_CONNECTOR_HOST=127.0.0.1
export DB_PORT=5432
# in our example database will running on the same host
export DB_HOST=127.0.0.1

export EXAMPLE_ACRA_CONNECTOR_API_ADDRESS=http://${ACRA_CONNECTOR_HOST}:${ACRA_CONNECTOR_PORT}
export EXAMPLE_HOST=127.0.0.1
export EXAMPLE_PORT=9494
export EXAMPLE_DB_USER=test
export EXAMPLE_DB_PASSWORD=test
export EXAMPLE_DB_NAME=test
export EXAMPLE_PUBLIC_KEY=docker/.acrakeys/acra-writer/${ACRA_CLIENT_ID}_storage.pub
# for mysql use EXAMPLE_MYSQL=true
export EXAMPLE_POSTGRESQL=true
```
You can setup it with one command:
```
source examples/python/example_environment.sh
```
*Note: you can override some value in file locally before running this command*


# General
Scripts have next required params:
* `db_name`
* `db_user`
* `db_password`
* `host` (of database)
* `port` (of database)
* `postgresql` or `mysql` (depends on database you use)

All args can be passed via environment variables with names `EXAMPLE_<UPPER_ARG_NAME>`. For example `EXAMPLE_DB_NAME` or `EXAMPLE_PORT`

Other params depends on mode (with zone or without) and type of action (`print` to list rows from db or `data` to add encrypted data to database)

*Note: in examples belowe we will explicitly set `--host` and `--port` to show how to run with environment when database running on separate host. If you run with docker-compose and have access to acra-connector and database from localhost then you can not pass `--host` parameter to script. Then will be used value from `EXAMPLE_HOST` environment variable*

**Important**

If you use MySQL database then you should pass `--mysql` parameter in each example or `--postgresql` (used as default and may be omitted) if you use PostgreSQL as database

## Printing decrypted data
To see decrypted data you must use port of AcraConnector (default 9494). If you will print using databases port then you will see encrypted data

# Without zone

## Insert data
```
python examples/python/example_without_zone.py --host=${DB_HOST} --port=${DB_PORT} --data="some data"
```
Output:
```
insert data: some data
```
## Print data

```
python examples/python/example_without_zone.py --host=${ACRA_CONNECTOR_HOST} --port=${ACRA_CONNECTOR_PORT} --print
```
Output:
```
id  - data                 - raw_data
14  - some data            - some data
```
*Use AcraConnector's host:port to see encrypted data and databases host:port to see encrypted data*

# With zone

## Insert data
```
python examples/python/example_with_zone.py --host=${ACRA_CONNECTOR_HOST} --port=${ACRA_CONNECTOR_PORT} --data="some data"
```

Then you will see next output with generated `zone_id`:
```
data: some data
zone: DDDDDDDDKbYPUFOEyryvaQda
```
To print decrypted value you must use zone id from output (`DDDDDDDDKbYPUFOEyryvaQda` in this example)
## Print data
Use zone id of row that you want to decrypt (`DDDDDDDDKbYPUFOEyryvaQda` for example):
```
python examples/python/example_with_zone.py --host=${ACRA_CONNECTOR_HOST} --port=${ACRA_CONNECTOR_PORT} --print --zone_id=DDDDDDDDKbYPUFOEyryvaQda
```
Output:
```
use zone_id:  DDDDDDDDKbYPUFOEyryvaQda
id  - zone - data - raw_data
6   - DDDDDDDDKbYPUFOEyryvaQda - some data - some data
```
*Use AcraConnector's host:port to see encrypted data and databases host:port to see encrypted data*

Add one more row with another zone id:
```
python examples/python/example_with_zone.py --host=${ACRA_CONNECTOR_HOST} --port=${ACRA_CONNECTOR_PORT} --data="some data2"
```

Then you will see next output with **new** generated `zone_id`:
```
data: some data2
zone: DDDDDDDDxPRPOLaykcSWiPqn
```
Now if you will print data from table with specific ZoneId you will see decrypted data only that was encrypted with this ZoneId. Other data will be in encrypted view:
```
python examples/python/example_with_zone.py --host=${ACRA_CONNECTOR_HOST} --port=${ACRA_CONNECTOR_PORT} --print --zone_id=DDDDDDDDKbYPUFOEyryvaQda
```
Output:
```
use zone_id:  DDDDDDDDKbYPUFOEyryvaQda
id  - zone - data - raw_data
6   - DDDDDDDDKbYPUFOEyryvaQda - some data - some data
7   - DDDDDDDDKbYPUFOEyryvaQda -  """"""""UEC2-[x[iUîZB_OcWUVs&YQK^@Su`t5@yPF(q^?yNCSX/ - some data2
```

Row with `id=7` will contain binary unprintable data in output. 