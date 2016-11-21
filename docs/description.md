# How to use from source
## install libssl
```
sudo apt-get install libssl-dev
```
## installing themis
```
git clone https://github.com/cossacklabs/themis.git /tmp/themis
cd /tmp/themis
sudo make SECURE_COMPARATOR=enable install
```

## building ssproxy and acra_gen_keys
```
cd /tmp
git clone https://ph.cossacklabs.com/diffusion/ACRA/acra.git
cd acra

sudo apt-get install golang

export GOPATH=`pwd`
go get github.com/cossacklabs/themis/gothemis/...
go build ssproxy
go build acra_gen_keys
```

## generating keys
* open 159.203.178.98
* copy command from website 
```./acra_gen_keys -key_name=<client_id>```
* run
* choose public key in ~/.ssession/<client_id>.pub on website and press "Send"
* Download server's key and put in ~/.ssession
## run ssproxy
Run command with correct <client_id>
```
./ssproxy -acra_host="159.203.178.98" -client_id=<client_id> -port=5433 -v
```

## setup for writing
\# libpq-dev libpython-dev libpython3-dev for psycopg2
```
sudo apt-get install python-virtualenv libpq-dev libpython-dev
virtualenv /tmp/test_env
source /tmp/test_env/bin/activate
pip install sqlalchemy pythemis psycopg2
```
## insert some data
\# with your <client_id> and text in --data arg
```
cd wrappers/python
PYTHONPATH=`pwd` python acra/sqla.py --client_id=<client_id> --db_user=acra --db_password=6JtaTrjqN69ZYhp4 --port=5433 --data "some_text"
```

## check that data encrypted
* open 159.203.178.98/phppgadmin/
```
login: acra
password: 6JtaTrjqN69ZYhp4
```

* choose "acra" database and "test" table
* in column "data" stored encrypted data and in column "raw_data" data as is that you inserted

## view decrypted data
\# the same as for inserting with --print arg and without --data
```
PYTHONPATH=`pwd` python acra/sqla.py --client_id=<client_id> --db_user=acra --db_password=6JtaTrjqN69ZYhp4 --port=5433 --print
```