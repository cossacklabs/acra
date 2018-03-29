# docker

  * `acra-build.dockerfile` - intermediate image for compile all acra components
  * `acraserver.dockerfile` - resulting image with acraserver
  * `acraproxy.dockerfile` - resulting image with acraproxy
  * `acra_genkeys.dockerfile` - resulting image with acra_genkeys

## Build containers

```
make docker
```

# docker-compose

  * `docker-compose-pgsql-ssession.yml` - postgresql, acraserver, acraproxy
    with SecureSession interconnection


## Quick launch

!!!!!!!!!!!!!!!!!!!!!!!!!!!
!!! INSECURE, TEST ONLY !!!
!!!!!!!!!!!!!!!!!!!!!!!!!!!
```
docker-compose -f docker/<compose_file_name>.yml up
```
This will create `docker/.acrakeys` directory structure, generate all key pairs,
put them to appropriate servcies' directories and launch all components.

Now you can connect to 9494/tcp (acraproxy) or 5432/tcp (postgresql).


## Normal launch

Please specify ACRA_MASTER_KEY:
```
export ACRA_MASTER_KEY=$(echo -n "My_Very_Long_Key_Phrase_ge_32_chars" | base64)
```

Also you probably want to define client id
```
export ACRA_CLIENT_ID="MyClientID"
```

Optionally you may specify docker image tag, which can be one of:
  * `stable` or `latest` - stable branch, recommended, default
  * `master` or `current` - master branch of github repository
  * `<full_commit_tag>` - specify the exact commit in repository
  * `<version>` - choose version tag
```
# Examples:
# branch
ACRA_DOCKER_IMAGE_TAG="master"
# commit tag
ACRA_DOCKER_IMAGE_TAG="2d2348f440aa0c20b20cd23c49dd34eb0d42d6a5"
# version
ACRA_DOCKER_IMAGE_TAG="0.76-33-g8b16bc2"
```

Now you can run docker-compose:
```
    docker-compose -f docker/docker-compose-pgsql-ssession.yml up
```
