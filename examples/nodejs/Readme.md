See a verbose explanation of how to prepare environment and use the examples in [https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker/](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker/). The explanation is provided for Python, some minor tweaks might be needed to get Acra examples run with Node.js.

These examples are simple as it may be with hardcoded values (sorry) just to see how you should create acrastructs and see decrypted data from database. Script will do next: encrypt data, save to database, fetch from database and print.
  
# Without zone
You can override next values in script to adapt to your environment:
* `raw_data` - message that will be encrypted and saved to db
* `config` - replace host|port|database|user|password with your settings for PostgreSQL. Use AcraConnector's host:port to print decrypted data and database's host:port to print encrypted data
* `acra_key` - replace `client_storage.pub` with yours correct path to storage public key 

## Run
```
nodejs examples/nodejs/examples_without_zones.js
```

# With zone

You can override next values in script to adapt to your environment:
* `res` - you may replace `http://127.0.0.1:9191/getNewZone` value with correct AcraConnector's host:port
* `raw_data` - message that will be encrypted and saved to db
* `config` - replace host|port|database|user|password with your settings for PostgreSQL. Use AcraConnector's host:port to print decrypted data and database's host:port to print encrypted data

## Run
```
nodejs examples/nodejs/examples_with_zone.js
```