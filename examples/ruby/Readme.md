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

## Установка гема acra
Перед запуском нужно установить gem acra.
До тех пор, пока гема нет в публичном доступе:
```
cd wrappers/ruby
gem build acra.gemspec
gem install ./acra-1.0.0.gem
cd -
```

## Без зон
Перед запуском:
* сгенерируйте пару ключей для ssproxy `go run src/acra_genkeys/acra_genkeys.go -key_name=client`
* сгенерируйте пару ключей для acra `go run src/acra_genkeys/acra_genkeys.go -key_name=client_server`
* запустите acra и укажите ip postgresql ((в моем случае запускаю акру, ssproxy и postgresql локально на одной машине) `go run src/acra/main/main.go -db_host=127.0.0.1`
* запустите ssproxy указав ip акры и client_id `go run src/ssproxy/ssproxy.go -client_id=client -acra_host=127.0.0.1`
* в examples/ruby/example.rb задайте свои параметры в `PG.connect(...)`

Запуск:

`ruby examples/ruby/example.rb`

Вы увидите:
```
data | raw_data
XUFCEDTO | XUFCEDTO
```

## С зонами

Перед запуском:
* сгенерируйте пару ключей для ssproxy `go run src/acra_genkeys/acra_genkeys.go -key_name=client`
* сгенерируйте пару ключей для acra `go run src/acra_genkeys/acra_genkeys.go -key_name=client_server`
* запустите acra и укажите ip postgresql ((в моем случае запускаю акру, ssproxy и postgresql локально на одной машине) `go run src/acra/main/main.go -db_host=127.0.0.1 -z`
* запустите ssproxy указав ip акры и client_id `go run src/ssproxy/ssproxy.go -client_id=client -acra_host=127.0.0.1`
* в examples/ruby/example_with_zone.rb задайте свои параметры в `PG.connect(...)`
* добавьте зону `go run src/addzone/addzone.go`. Получите json строку с 
данными зоны. Подставьте в examples/ruby/example_with_zone.rb в строке `zone_data = JSON.parse('{...}')` 

Запуск:

`ruby examples/ruby/example_with_zone.rb`

Вы увидите:
```
zone | data | raw_data
ZXCfelcOOnfYWkVphBn | DUEYYINX | DUEYYINX
```


Что бы убедиться что данные на самом деле зашифрованы, замените в 
`PG.connect(...)` порт с ssproxy на postgresql (5432) и запустите еще раз. 
Вы увидите в консоли вместо `data` крякозябры.
Либо напрямую подключитесь к postgresql через его порт (не через ssproxy) используя
psql и сделайте `SELECT`.