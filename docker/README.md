# docker

  * `acra-build.dockerfile` - intermediate image for compile all acra components
  * `acraserver.dockerfile` - resulting image with acraserver
  * `acraproxy.dockerfile` - resulting image with acraproxy
  * `acra_genkeys.dockerfile` - resulting image with acra_genkeys
  * `mysql-ssl.dockerfile` - MySQL server container with example SSL
    certificates (located at ssl/mysql directory)
  * `postgresql-ssl.dockerfile` - Postgresql server container with example SSL
    certificates (located at ssl/postgresql directory)

## Build containers

```bash
make docker
```

# docker-compose

There are examples with different interconnection types (`client` is not
included into composes and is given only to indicate its position):
  * `docker-compose.mysql-nossl-server-ssession-proxy.yml`
    mysql <-> acraserver <-SecureSession-> acraproxy <-> client
  * `docker-compose.mysql-ssl-server-ssl.yml`
    mysql <-SSL-> acraserver <-SSL-> client
  * `docker-compose.pgsql-nossl-server-ssession-proxy.yml`
    postgresql <-> acraserver <-SecureSession-> acraproxy <-> client
  * `docker-compose.pgsql-nossl-server-ssession-proxy_zonemode.yml`
    postgresql <-> acraserver <-SecureSession-> acraproxy <-> client in zone mode
  * `docker-compose.pgsql-ssl-server-ssl.yml`
    postgresql <-SSL-> acraserver <-SSL-> client


## Quick launch

INSECURE, TEST ONLY!
```bash
docker-compose -f docker/<compose_file_name>.yml up
```
This will create `docker/.acrakeys` directory structure, generate all key pairs,
put them to appropriate services' directories and launch all components.

Now you can connect to:
  * 9494/tcp (acraproxy)
  * 9191/tcp (acraproxy API) in zone mode
  * 5432/tcp (postgresql) or 3306/tcp (mysql)


## Normal launch

Please specify ACRA_MASTER_KEY:
```bash
export ACRA_MASTER_KEY=$(echo -n "My_Very_Long_Key_Phrase_ge_32_chars" | base64)
```

Also you probably want to define client id
```bash
export ACRA_CLIENT_ID="MyClientID"
```

Optionally you may specify docker image tag, which can be one of:
  * `stable` or `latest` - stable branch, recommended, default
  * `master` or `current` - master branch of github repository
  * `<full_commit_tag>` - specify the exact commit in repository
  * `<version>` - choose version tag
```bash
# Examples:
# branch
ACRA_DOCKER_IMAGE_TAG="master"
# commit tag
ACRA_DOCKER_IMAGE_TAG="2d2348f440aa0c20b20cd23c49dd34eb0d42d6a5"
# version
ACRA_DOCKER_IMAGE_TAG="0.76-33-g8b16bc2"
```

Please define database name and user credentials:
```
# for Postgresql
export POSTGRES_DB="<db_name>"
export POSTGRES_USER="<user_name>"
export POSTGRES_PASSWORD="<user_password>"

# for MySQL
export MYSQL_ONETIME_PASSWORD="<mysql_onetime_password>"
export MYSQL_ROOT_PASSWORD="<mysql_root_password>"
export MYSQL_DATABASE="<db_name>"
export MYSQL_USER="<user_name>"
export MYSQL_PASSWORD="<user_password>"
```

Now you can run docker-compose:
```bash
    docker-compose -f docker/<compose_file_name> up
```
