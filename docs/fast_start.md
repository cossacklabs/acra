```
go build acra_gen_keys
./acra_gen_keys -key_name=client
./acra_gen_keys -key_name=client_server
go build acra/main
go build ssproxy
# use yours port and host
go run src/acra/main/main.go -db_host=172.17.0.1 -db_port=5433 -d
# another tab
go run src/ssproxy/ssproxy.go -acra_host=127.0.0.1 -v -client_id=client -port=9494
```