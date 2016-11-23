# Пример использования acra
## Установка themis
```
git clone https://github.com/cossacklabs/themis.git
cd themis
make
sudo make install
```

## Загрузка acra
```
git clone https://ph.cossacklabs.com/diffusion/ACRA/acra.git
cd acra
```

## Без зон
Перед запуском:
* сгенерируйте пару ключей для ssproxy `go run src/acra_genkeys/acra_genkeys.go -key_name=client`
* сгенерируйте пару ключей для acra `go run src/acra_genkeys/acra_genkeys.go -key_name=client_server`
* запустите acra и укажите ip postgresql ((в моем случае запускаю акру, ssproxy и postgresql локально на одной машине) `go run src/acra/main/main.go -db_host=127.0.0.1`
* запустите ssproxy указав ip акры и client_id `go run src/ssproxy/ssproxy.go -client_id=client -acra_host=127.0.0.1`
* в examples/golang/src/example/example.go задайте свои параметры в `const CONNECTION_STRING string = "..."`

Запуск:

`go run examples/golang/src/example/example.go`

Вы увидите:
```
Generated test data: SyURoaeoRktPlbAPRiLR
Create test table with command: 'CREATE TABLE IF NOT EXISTS test(id INTEGER PRIMARY KEY, data BYTEA, raw_data TEXT);'
Insert test data to table
Select from db with command: 'SELECT data, raw_data FROM test;'
data - raw_data
data: SyURoaeoRktPlbAPRiLR
raw_data: SyURoaeoRktPlbAPRiLR
```

## С зонами

Перед запуском:
* сгенерируйте пару ключей для ssproxy `go run src/acra_genkeys/acra_genkeys.go -key_name=client`
* сгенерируйте пару ключей для acra `go run src/acra_genkeys/acra_genkeys.go -key_name=client_server`
* запустите acra и укажите ip postgresql ((в моем случае запускаю акру, ssproxy и postgresql локально на одной машине) `go run src/acra/main/main.go -db_host=127.0.0.1 -z`
* запустите ssproxy указав ip акры и client_id `go run src/ssproxy/ssproxy.go -client_id=client -acra_host=127.0.0.1`
* в examples/golang/src/example/example_with_zone.go задайте свои параметры в `const CONNECTION_STRING string = "..."`
Запуск:

`go run examples/golang/src/example/example_with_zone.go`

Вы увидите:
```
Generated test data: VjABAYHixSIQEAsdzPfD
Create test table with command: 'CREATE TABLE IF NOT EXISTS test2(id INTEGER PRIMARY KEY, zone BYTEA, data BYTEA, raw_data TEXT);'
Insert test data to table
Select from db with command: 'SELECT zone, data, raw_data FROM test2;'
zone, data - raw_data
zone: ZXCPxToqifJkNbnSFnc
data: pgwRxzKnRWmNAhVNxHUU
raw_data: pgwRxzKnRWmNAhVNxHUU
```


Что бы убедиться что данные на самом деле зашифрованы, замените в 
`CONNECTION_STRING` порт с ssproxy на postgresql (5432) и запустите еще раз. 
Вы увидите в консоли вместо `data` крякозябры.
Либо напрямую подключитесь к postgresql через его порт (не через ssproxy) используя
psql и сделайте `SELECT`.

## Примечание
При подключении к postgresql вы должны явно выключить ssl и запретить использовать
бинарный формат данных для prepared statements, что бы postgresql использовал 
текстовый формат (в будущем возможно добавиться поддержка бинарного формата). Т.е. нужно в параметры подключения добавить следующие параметры:
```
sslmode=disable disable_prepared_binary_result=yes
```