# Setup and run postgreSQL database

You can run database on your local machine or using docker. The easiest option is to use `docker-compose.yml` we provide.

```console
docker-compose up
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
python -m grpc_tools.protoc -I cmd/acra-translator/grpc_api --python_out=tests/ --grpc_python_out=tests/ cmd/acra-translator/grpc_api/api.proto
```

# Run tests

If you want to customise database settings, pass them as environment variables:

```console
TEST_TLS=off TEST_SSL_MODE=allow TEST_DB_HOST=127.0.0.1 TEST_DB_USER=postgres TEST_DB_USER_PASSWORD=postgres TEST_DB_NAME=postgres TEST_DB_PORT=5432  python3 tests/test.py
``` 

or just use default database settings

```console
python3 tests/test.py
```
