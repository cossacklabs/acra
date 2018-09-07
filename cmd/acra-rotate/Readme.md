## Database rotation

### Queries
To rotate data in database you should write to sql queries:
1. sql_select - should fetch data from database where last 2 columns (other columns will be passed to "update query") in result would be ZoneId and AcraStruct
2. sql_update - should update/insert data to database and use at least 1 placeholder where will be placed rotated AcraStruct. All other placeholders will containt other data which returned by sql_select in the same order

Example:
```
create table Test (
 id INTEGER
 superuser BOOLEAN
 zone_id BINARY
 data BINARY
)
```

For example we want to rotate all data related with entries that has `superuser` field with `TRUE` value then we should use next queries:
1. Update by id:

* sql_select - `select id, zone_id, data from Test where superuser=True;`
* sql_update - `update Test set data=$1 where id=$2`

2. Update by `zone_id` column:

Because required field of `zone_id` we don't pass as placeholder values to `sql_update` query we need to fetch it twice:

* sql_select - `select zone_id, zone_id, data from Test where superuser=True`
* sql_update - `update Test set data=$1 where zone_id=$2`

3. Insert rotated data to another table:

```
create table TestDataBackup (
 id INTEGER
 data BINARY
)
```

* sql_select - `select id, data from Test`
* sql_update - `insert into Test values ($2, $1);` (here we place rotated AcraStruct as placeholder $1 and set it as second `values` value)

Or we can just declare another order of columns in query:
* sql_update - `insert into Test (data, id) values ($1, $2);` - here we declare that we will insert in order `(data, id)` instead declared on table creation

### Value placeholders
You should use next placeholder values:
* postgresql: $n, $n+1, $n+2. `insert into table values($1, $2, $3)`
* mysql: ?, ?, ?. `insert into table value(?, ?, ?)`

### Connection strings
You should use next connection string formats:
* postgresql: use format from [github.com/lib/pq](https://godoc.org/github.com/lib/pq) - `"postgres://<USERNAME>:<PASSWORD>@<HOST>:<PORT>/<DATABASE>?<param1>=<param1-value>"`
* mysql: use format from [github.com/go-sql-driver/mysql](https://github.com/go-sql-driver/mysql) - `[username[:password]@][protocol[(address)]]/dbname[?param1=value1&...&paramN=valueN]`

### Running
PostgreSQL:
```
$GOPATH/bin/acra-rotate --keys_dir=/path/to/zone-private-keys --postgresql_enable --sql_select="select id, data from Test" --sql_update="insert into Test (data, id) values ($1, $2);" --connection_string="postgres://test:test@127.0.0.1:5432/test"
```

MySQL:
```
$GOPATH/bin/acra-rotate --keys_dir=/path/to/zone-private-keys --mysql_enable --sql_select="select id, data from Test" --sql_update="insert into Test values (?, ?);" --connection_string="test:test@tcp(127.0.0.1:3306)/test"
```      

## File rotation

Before running rotation of keys and data in files you should generate json config for it with "zone id" as key and list with paths to files which was encrypted with this zone id
```
{
  "<ZONE ID1>": ["/path/to/file/acrastruct1", "/path/to/file/acrastruct2", "/path/to/file/acrastruct3"],
  "<ZONE ID2>": ["/path/to/file/acrastruct1", "/path/to/file/acrastruct2", "/path/to/file/acrastruct3"],
}
```
Then run rotation:
```
$GOPATH/bin/acra-rotate --keys_dir=/path/to/zone-private-keys --file_map_config=/path/to/config.json
```
Output like:
```
{
    "DDDDDDDDFSckOyJqVmENXawn": {
        "new_public_key": "VUVDMgAAAC1Vq8RnA4Q1BJnUye29lkj0rbSImHiKRPzzPxp1use2BGPYCug+",
        "file_paths": [
            "/tmp/tmpchz_kgy5/DDDDDDDDFSckOyJqVmENXawn_0.acrastruct",
            "/tmp/tmpchz_kgy5/DDDDDDDDFSckOyJqVmENXawn_1.acrastruct",
            "/tmp/tmpchz_kgy5/DDDDDDDDFSckOyJqVmENXawn_2.acrastruct"
        ]
    },
    "DDDDDDDDNWuqISbEdXtokBfu": {
        "new_public_key": "VUVDMgAAAC10hAftA3sOEp9qhe5h0yWugZb1DHEpj0BUK+5WE1/h9FDvKEsO",
        "file_paths": [
            "/tmp/tmpchz_kgy5/DDDDDDDDNWuqISbEdXtokBfu_0.acrastruct",
            "/tmp/tmpchz_kgy5/DDDDDDDDNWuqISbEdXtokBfu_1.acrastruct",
            "/tmp/tmpchz_kgy5/DDDDDDDDNWuqISbEdXtokBfu_2.acrastruct"
        ]
    },
    "DDDDDDDDUIUNdhWUSIXlTczw": {
        "new_public_key": "VUVDMgAAAC0hvsSPA78cxoxHOeEVZtwJT6bhK1SWNLj0J+GjRD7j5kZwb8Be",
        "file_paths": [
            "/tmp/tmpchz_kgy5/DDDDDDDDUIUNdhWUSIXlTczw_0.acrastruct",
            "/tmp/tmpchz_kgy5/DDDDDDDDUIUNdhWUSIXlTczw_1.acrastruct",
            "/tmp/tmpchz_kgy5/DDDDDDDDUIUNdhWUSIXlTczw_2.acrastruct"
        ]
    }
}
```