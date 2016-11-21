#This document describe how deploy localy postgresql + acra + proxy + app with docker
```
docker run -p 5433:5432 --name postgres_instance -e POSTGRES_PASSWORD=acra -e POSTGRES_DB=acra -e POSTGRES_USER=acra -d postgres
git clone https://ph.cossacklabs.com/diffusion/ACRA/acra.git
cd acra
docker build --build-arg HTTP_LOGIN=LOGIN --build-arg HTTP_PASSWORD=PASSWORD -t acra -f docker/acra  docker
docker build --build-arg HTTP_LOGIN=LOGIN --build-arg HTTP_PASSWORD=PASSWORD -t ssproxy -f docker/ssproxy  docker
docker run --link postgres_instance:postgres_link --name acra_instance -d acra ./main -db_host=postgres_link -keys_dir=/keys -v
docker run --link acra_instance:acra_link --name ssproxy_instance -d -p 9494:9494 ssproxy ./ssproxy -acra_host=acra_link -client_id=client -keys_dir=/keys -v
./acra_gen_keys
docker cp ~/.ssession/client ssproxy_instance:/keys/client
docker cp ~/.ssession/client_server.pub ssproxy_instance:/keys/client_server.pub
./acra_gen_keys -key_name=client_server
docker cp ~/.ssession/client_server acra_instance:/keys/client_server
docker cp ~/.ssession/client.pub acra_instance:/keys/client.pub
docker build --build-arg HTTP_LOGIN=<LOGIN> --build-arg HTTP_PASSWORD=<PASSWORD> -t acra_app -f docker/application docker
docker run --link ssproxy_instance:ssproxy_link --rm -v ~/.ssession/client_server.pub:/root/.ssession/client_server.pub acra_app --db_password=acra --client_id=client --data "Some new data"
docker run --link ssproxy_instance:ssproxy_link --rm -v ~/.ssession/client_server.pub:/root/.ssession/client_server.pub acra_app --db_password=acra --client_id=client --print
psql -h127.0.0.1 --port=5433 --dbname=acra -Uacra
```

## Description

### Run postgresql as docker instance
`docker run -p 5433:5432 --name postgres_instance -e POSTGRES_PASSWORD=acra -e POSTGRES_DB=acra -e POSTGRES_USER=acra -d postgres`

Here we run instance of postgresql and set port mapping from container's 5432 to host 5433 port and password for 'postgres' user

### Download code from repo
```
git clone https://ph.cossacklabs.com/diffusion/ACRA/acra.git
cd acra
```
#### Build image of acra
`docker build --build-arg HTTP_LOGIN=LOGIN --build-arg HTTP_PASSWORD=PASSWORD -t acra -f docker/acra  docker`

*note: due to using our private repository in https://ph.cossacklabs.com which not supporting ssh keys, we need tell credentials. When repo will public it wouldn't need to do*
- `--build-arg HTTP_LOGIN=LOGIN` - its username for repository on https://ph.cossacklabs.com
- `--build-arg HTTP_PASSWORD=PASSWORD` - its username for repository on https://ph.cossacklabs.com
- `-t acra` - name our image 'acra'
- `-f docker/acra` - tell which dockerfile to use
- `docker` - build context

#### Build image of ssproxy
`docker build --build-arg HTTP_LOGIN=LOGIN --build-arg HTTP_PASSWORD=PASSWORD -t ssproxy -f docker/ssproxy  docker`

Our preparation is finished

#### Run acra instance
`docker run --link postgres_instance:postgres_link --name acra_instance -d acra ./main -db_host=postgres_link -keys_dir=/keys -v`
- `--link postgres_instance:postgres_link` - tell docker that he should give access to postgres_instance via network and it will with name postgres_link
- `--name acra_instance` - name our instance
- `-d` - daemonize our instance
- `acra` - tell what image to use
- `./main -db_host=postgres_link -keys_dir=/keys -v` - command to execute in instance
- - `-db_host=postgres_link` - tell host of our postgresql instance
- - `-keys_dir=/keys` - here we should place keys to container later
- - `-v` - verbose mode to view logs

#### Run ssproxy instance
`docker run --link acra_instance:acra_link --name ssproxy_instance -d -p 9494:9494 ssproxy ./ssproxy -acra_host=acra_link -client_id=client -keys_dir=/keys -v`
- `--link acra_instance:acra_link` - add network access to our acra instance by hostname acra_link
- `--name ssproxy_instance` - name instance
- `-d` - daemonize instnace
- `-p 9494:9494` - map port from instance to host machine for connecting via app or psql later
- `ssproxy` - tell what image to use
- `./ssproxy -acra_host=acra_link -client_id=client -keys_dir=/keys -v` - execute command in instance
- - `-acra_host=acra_link` - host to acra that we declared above
- - `-client_id=client` - name of client for which we should generate keys later ('client' can be any id name with at least 5 char length)
- - `-keys_dir=/keys` - tell where we will place keys
- - `-v` - verbose mode

#### Generate keys for acra and client
```
go build acra_gen_keys
# generate for client (client is default key name)
./acra_gen_keys
# generate for acra (keys for acra must have name like client's with _server suffix)
./acra_gen_keys -key_name=client_server
```
All keys were generated to ~/.ssession directory
#### Put keys to instances
Copy client's private key and acra's public key into ssproxy instance
```
docker cp ~/.ssession/client ssproxy_instance:/keys/client
docker cp ~/.ssession/client_server.pub ssproxy_instance:/keys/client_server.pub
```
Copy acra's private key and client's public key into acra instance
```
docker cp ~/.ssession/client_server acra_instance:/keys/client_server
docker cp ~/.ssession/client.pub acra_instance:/keys/client.pub
```
#### Connect to our database using ssproxy through acra to postgresql
`psql -h127.0.0.1 --port=5433 --dbname=acra -Uacra`

*use password that we pass as arg to postgresql_instance above (acra)*
Check that data is encrypted and unreadable
`select * from test;`

#### Add some data to db
Build acra app

`docker build --build-arg HTTP_LOGIN=<LOGIN> --build-arg HTTP_PASSWORD=<PASSWORD> -t acra_app -f docker/application  docker`

Now we can use our image for inserting

`docker run --link ssproxy_instance:ssproxy_link --rm -v ~/.ssession/client_server.pub:/root/.ssession/client_server.pub acra_app --db_password=acra --client_id=client --data "Some new data"`

- `--link ssproxy_instance:ssproxy_link` give access to running ssproxy instance
- `--rm` - delete docker container after executing command
- `-v /path/to/downloaded/pubkey:/root/.ssession/<CLIENT_ID>_server.pub` - put public key into instance. use your path to previously downloaded server's public key
- `acra_app` - name of builded image
- `--client_id=client --data "Some new data"` - args to script 
- - `--client_id=client` - client id for which we generated keys
- - `--data "Some new data"` - data to insert into db

And print data

`docker run --link ssproxy_instance:ssproxy_link --rm -v ~/.ssession/client_server.pub:/root/.ssession/client_server.pub acra_app --db_password=acra --client_id=client --print`

Difference in last arg where we replace `--data "Some new data"` to `--print`