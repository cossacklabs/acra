#Decrypting acrastructs encrypted without zones
You need pass as args:
* select sql query for fetching data from db `-select "select data from data_table;"`
* insert sql query with placeholder `$1` in which place will be inserted data or 
binded for inserting directly to db (if you will use `-execute` param) `-insert 'insert into test_insert(data) values($1);`
* client id for finding key `-client_id=onekey`
* connection string that will be used to connect to db `-connection_string="dbname=some_database user=postgres password=postgres host=127.0.0.1 port=5432"`
Script will search key in `.acrakeys` folder with name <client_id>, generate sql 
insert queries to file `decrypted.sql`. If you use `-execute` arg, script will 
insert data to db too. If you need just insert to db without generating output file, pass empty filename like `-output=""`
```
./acra_rollback -select "select data from data_table;" -insert 'insert into test_insert(data) values($1);' -connection_string="dbname=some_database user=postgres password=postgres host=127.0.0.1 port=5432" -client_id=onekey
```

#Decrypting acrastructs encrypted with zones
The same but:
* use `-zonemode` param
* you don't need pass client id
* your SELECT sql query must fetch zone and data from db and zone should be first `-select "select zone, data from data_table;"`
* all zone private keys should be placed in keys dir (.acrakeys default)
```
./acra_rollback -select "select zone, data from data_table;" -insert 'insert into test_insert(data) values($1);' -connection_string="dbname=some_database user=postgres password=postgres host=127.0.0.1 port=5432" -zonemode
```
