# docker

  * `acra-build.dockerfile` - intermediate image for compile all acra components
  * `acraserver.dockerfile` - resulting image with acraserver
  * `acraproxy.dockerfile` - resulting image with acraproxy
  * `acra_configui.dockerfile` - resulting image with acra_configui component
  * `acra_genkeys.dockerfile` - resulting image with acra_genkeys tool
  * `acra_genauth.dockerfile` - resulting image with acra_genauth tool
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

  * `docker/docker-compose.pgsql-nossl-server-ssession-proxy.yml`
    pgsql <-> acraserver <-SecureSession-> acraproxy <---> client
                                                       '-> acra_configui
  * `docker/docker-compose.pgsql-nossl-server-ssession-proxy_zonemode.yml`
    pgsql <-> acraserver <-SecureSession-> acraproxy <---> client in zone mode
                                                       '-> acra_configui
  * `docker/docker-compose.pgsql-nossl-server-ssl-proxy.yml`
    pgsql <-> acraserver <-SSL-> acraproxy <-SSL-> client
  * `docker/docker-compose.pgsql-nossl-server-ssl-proxy_zonemode.yml`
    pgsql <-> acraserver <-SSL-> acraproxy <-SSL-> client in zone mode
  * `docker/docker-compose.pgsql-ssl-server-ssl-proxy.yml`
    pgsql <-SSL-> acraserver <-SSL-> acraproxy <-SSL-> client
  * `docker/docker-compose.pgsql-ssl-server-ssl_zonemode.yml`
    pgsql <-SSL-> acraserver <-SSL-> client in zone mode


## Quick launch

INSECURE, TEST ONLY!
```bash
docker-compose -f docker/<compose_file_name>.yml up
```
This will create `docker/.acrakeys` directory structure, generate all key pairs,
put them to appropriate services' directories and launch all components.

Now you can connect to:
  * 9494/tcp (acraproxy)
  * 8000/tcp (acra_configui) in configurations with acraproxy
  * 5432/tcp (postgresql)


## Normal launch

Docker containers with names `acra_genkeys_*` and `acra_genauth` were added to
docker-compose files for architecture demonstration and quick start purposes
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

For access to acra_configui HTTP interface you can define:
```
export ACRA_HTTPAUTH_USER=<http_auth_user>
export ACRA_HTTPAUTH_PASSWORD=<http_auth_password>
```

Now you can run docker-compose:
```bash
    docker-compose -f docker/<compose_file_name> up
```
