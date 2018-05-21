# docker

  * `acra-build.dockerfile` - intermediate image for compile all acra components
  * `acra-server.dockerfile` - resulting image with AcraServer
  * `acra-connector.dockerfile` - resulting image with AcraConnector
  * `acra-webconfig.dockerfile` - resulting image with AcraWebconfig component
  * `acra-keymaker.dockerfile` - resulting image with AcraKeymaker tool
  * `acra-authmanager.dockerfile` - resulting image with AcraAuthmanager tool
  * `postgresql-ssl.dockerfile` - Postgresql server container with example SSL
    certificates (located at ssl/postgresql directory)

## Build containers

```bash
make docker
```

# docker-compose

## Requirements

Our docker-compose files were created using v3 compose file format. Please check
your docker engine and docker-compose versions with [docker official
compatibility table](https://docs.docker.com/compose/compose-file/compose-versioning/#compatibility-matrix).

## Configurations

There are examples with different interconnection types (`client` is not
included into composes and is given only to indicate its position):

  * `docker/docker-compose.pgsql-nossl-server-ssession-connector.yml`
    PostgreSQL <-> AcraServer <-SecureSession-> AcraConnector <---> client
                                                       '-> AcraWebconfig
  * `docker/docker-compose.pgsql-nossl-server-ssession-connector_zonemode.yml`
    PostgreSQL <-> AcraServer <-SecureSession-> AcraConnector <---> client in zone mode
                                                       '-> AcraWebconfig
  * `docker/docker-compose.pgsql-nossl-server-ssl-connector.yml`
    PostgreSQL <-> AcraServer <-SSL-> AcraConnector <-SSL-> client
  * `docker/docker-compose.pgsql-nossl-server-ssl-connector_zonemode.yml`
    PostgreSQL <-> AcraServer <-SSL-> AcraConnector <-SSL-> client in zone mode
  * `docker/docker-compose.pgsql-ssl-server-ssl-connector.yml`
    PostgreSQL <-SSL-> AcraServer <-SSL-> AcraConnector <-SSL-> client
  * `docker/docker-compose.pgsql-ssl-server-ssl_zonemode.yml`
    PostgreSQL <-SSL-> AcraServer <-SSL-> client in zone mode


## Quick launch

INSECURE, TEST ONLY!
```bash
docker-compose -f docker/<compose_file_name>.yml up
```
This will create `docker/.acrakeys` directory structure, generate all key pairs,
put them to appropriate services' directories and launch all components.

Now you can connect to:
  * 9494/tcp (acra-connector)
  * 8000/tcp (acra-webconfig) in configurations with AcraConnector
  * 5432/tcp (postgresql)


## Normal launch

Docker containers with names `acra-keymaker_*` and `acra-authmanager` were added
to docker-compose files for architecture demonstration and quick start purposes
only. You should remove them from selected compose file, generate and place all
keys manually.

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
export ACRA_DOCKER_IMAGE_TAG="master"
# commit tag
export ACRA_DOCKER_IMAGE_TAG="2d2348f440aa0c20b20cd23c49dd34eb0d42d6a5"
# version
export ACRA_DOCKER_IMAGE_TAG="0.76-33-g8b16bc2"
```

Please define database name and user credentials:
```
export POSTGRES_DB="<db_name>"
export POSTGRES_USER="<user_name>"
export POSTGRES_PASSWORD="<user_password>"
```

For access to AcraWebconfig HTTP interface you can define:
```
export ACRA_HTTPAUTH_USER=<http_auth_user>
export ACRA_HTTPAUTH_PASSWORD=<http_auth_password>
```

Now you can run docker-compose:
```bash
    docker-compose -f docker/<compose_file_name> up
```
