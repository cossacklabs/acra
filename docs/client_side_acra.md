# This document describe how run local proxy to acra and write/print data to/from db through acra with docker
```
git clone https://ph.cossacklabs.com/diffusion/ACRA/acra.git
cd acra
go build acra_gen_keys
./acra_gen_keys -key_name=<SERVER_GENERATED_CLIENT_ID>
docker build --build-arg HTTP_LOGIN=LOGIN --build-arg HTTP_PASSWORD=PASSWORD -t ssproxy -f docker/ssproxy docker
docker run --name ssproxy_instance -d -p 9494:9494 ssproxy ./ssproxy -acra_host=159.203.178.98 -client_id=client -keys_dir=/keys -v
docker cp ~/.ssession/<CLIENT_ID> ssproxy_instance:/keys/<CLIENT_ID>
docker cp ~/.ssession/<CLIENT_ID>_server.pub ssproxy_instance:/keys/<CLIENT_ID>_server.pub
docker build --build-arg HTTP_LOGIN=LOGIN --build-arg HTTP_PASSWORD=PASSWORD -t acra_app -f docker/application  docker
docker run --link ssproxy_instance:ssproxy_link --rm -v /path/to/downloaded/pubkey:/root/.ssession/<CLIENT_ID>_server.pub acra_app --db_password=6JtaTrjqN69ZYhp4 --client_id=<CLIENT_ID> --data "Some new data"
docker run --link ssproxy_instance:ssproxy_link --rm -v /path/to/downloaded/pubkey:/root/.ssession/<CLIENT_ID>_server.pub acra_app --db_password=6JtaTrjqN69ZYhp4 --client_id=<CLIENT_ID> --print
```


### Step 1 - Compile key generator
```
git clone https://ph.cossacklabs.com/diffusion/ACRA/acra.git
cd acra
```
Now let's compile key generator
```
go build acra_gen_keys
```

### Step 2 - Generate keys
- Open 159.203.178.98
- Copy command and run in terminal `./acra_gen_keys -key_name=SERVER_GENERATED_ID`
- Choose your public key on website and press "Send"
- Press "Download" and server's public key will be saved on your computer
- Copy downloaded key to ~/.ssession directory

### Step 3 - run instance of local proxy to acra

`docker build --build-arg HTTP_LOGIN=<LOGIN> --build-arg HTTP_PASSWORD=<PASSWORD> -t ssproxy -f docker/ssproxy  docker`
- `--build-arg HTTP_LOGIN=<LOGIN> --build-arg HTTP_PASSWORD=<PASSWORD>` - due to using private git repository on ph.cossacklabs.com you should use your LOGIN and PASSWORD

`docker run --name ssproxy_instance -d -p 9494:9494 ssproxy ./ssproxy -acra_host=159.203.178.98 -client_id=<CLIENT_ID> -keys_dir=/keys -v`
### Step 4 - Put generated private key and server's public key into proxy instance

```
docker cp ~/.ssession/<CLIENT_ID> ssproxy_instance:/keys/<CLIENT_ID>
docker cp ~/.ssession/<CLIENT_ID>_server.pub ssproxy_instance:/keys/<CLIENT_ID>_server.pub
```

### Step 5 - Add some data to db
Build acra app

`docker build --build-arg HTTP_LOGIN=<LOGIN> --build-arg HTTP_PASSWORD=<PASSWORD> -t acra_app -f docker/application  docker`

Now we can use our image for inserting

`docker run --link ssproxy_instance:ssproxy_link --rm -v /path/to/downloaded/pubkey:/root/.ssession/<CLIENT_ID>_server.pub acra_app --db_password=6JtaTrjqN69ZYhp4 --client_id=<CLIENT_ID> --data "Some new data"`

- `--link ssproxy_instance:ssproxy_link` give access to running ssproxy instance
- `--rm` - delete docker container after executing command
- `-v /path/to/downloaded/pubkey:/root/.ssession/<CLIENT_ID>_server.pub` - put public key into instance. use your path to previously downloaded server's public key
- `acra_app` - name of builded image
- `--db_password=6JtaTrjqN69ZYhp4 --client_id=<CLIENT_ID> --data "Some new data"` - args to script
- - `--db_password=6JtaTrjqN69ZYhp4` - password to db for acra user
- - `--client_id=<CLIENT_ID>` - client id that was generated on website
- - `--data "Some new data"` - data to insert into db

And print data

`docker run --link ssproxy_instance:ssproxy_link --rm -v /path/to/downloaded/pubkey:/root/.ssession/<CLIENT_ID>_server.pub acra_app --db_password=6JtaTrjqN69ZYhp4 --client_id=<CLIENT_ID> --print`

Difference in last arg where we replace `--data "Some new data"` to `--print`