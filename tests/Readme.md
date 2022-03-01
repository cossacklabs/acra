# Setup and run postgreSQL database

You can run database on your local machine or using docker. The easiest option is to use `docker-compose_postgres.yml` we provide.

```console
docker-compose -f tests/docker-compose_postgres.yml up
```

Make sure that database is up and running, and you can login as `postgres` user:

```console
docker ps -a
docker exec -it <container_name> /bin/bash
root@<container_id>:/# psql -U postgres
```

If you see error message `psql: FATAL:  role "postgres" does not exist` please make sure that `postgres` user is created. 


MacOS users may need to install postgreSQL locally and create `postgres` user, otherwise they continue seeing the error. Refer to this [StackOverflow issue](https://stackoverflow.com/a/35308200/2238082).

Your database should be up and running.

# Setup and run MySQL database

You can run database on your local machine or using docker. The easiest option is to use `ddocker-compose_mysql.yml` we provide.

```console
docker-compose -f tests/docker-compose_mysql.yml up
```

Make sure that database is up and running, and you can login as `test/test` user:

```console
docker ps -a
docker exec -it <container_name> /bin/bash
root@<container_id>:/# mysql -utest -ptest
```

# Install python requirements

```console
pip3 install -r tests/requirements.txt
```

# Setup fixed python mysql driver
```
git clone https://github.com/Lagovas/mysql-connector-python
cd mysql-connector-python
sudo python3 setup.py clean build_py install_lib
```

# Regenerate grpc code for python
```
python3 -m grpc_tools.protoc -I cmd/acra-translator/grpc_api --python_out=tests/ --grpc_python_out=tests/ cmd/acra-translator/grpc_api/api.proto
```

# Run tests

If you want to customise database settings, pass them as environment variables:

```console
TEST_TLS=off TEST_SSL_MODE=allow TEST_DB_HOST=127.0.0.1 TEST_DB_USER=postgres TEST_DB_USER_PASSWORD=postgres TEST_DB_NAME=postgres TEST_DB_PORT=5432 python3 tests/test.py
``` 

Connecting to MySQL

```console
TEST_TLS=off TEST_SSL_MODE=allow TEST_MYSQL=True TEST_DB_HOST=127.0.0.1 TEST_DB_USER=test TEST_DB_USER_PASSWORD=test TEST_DB_NAME=test TEST_DB_PORT=3306 python3 tests/test.py
``` 

or just use default database settings (connecting to PostgreSQL by default):

```console
python3 tests/test.py
```

To run test with HashiCorp Vault ACRA_MASTER_KEY loader

```console
VAULT_API_TOKEN=root_token TEST_WITH_VAULT=on VAULT_KV_ENGINE_VERSION={v1/v2} python3 tests/test.py
```

# Speed up local test runs

## Re-use generated test data

Set path to empty or not existing folder into `TEST_RANDOM_DATA_FOLDER` env variable where script will generate test data once 
and re-use everytime if folder exists. 
You can call generate data manually:
```
export TEST_RANDOM_DATA_FOLDER=/tmp/test_data
python3 tests/generate_random_data.py
```

# Skip cleaning built binaries to re-use not changed already compiled binaries

Before start testCases, test script build all acra binaries from `cmd/` folder into folder set in `TEST_BINARY_OUTPUT_FOLDER`
env variable (default: `/tmp`). When all tests finished, script delete all compiled binaries.
To turn off cleaning you can set `TEST_CLEAN_BINARIES=false` env variable. After that, next test run will re-use existing
binaries from folder or compile if they not exists. Script forks `go build` command, so golang's compiler tracks changes
in source code by itself and skip re-compilation if sources wasn't changed between compilations and test runs. You should
not clean folder or recompile manually after changing acra sources.

```
export TEST_BINARY_OUTPUT_FOLDER=/tmp/acra-binaries
export TEST_CLEAN_BINARIES=false
# after that this script will not delete compiled binaries
# and will compile them to "/tmp/acra-binaries" folder
python3 tests/test.py
```
