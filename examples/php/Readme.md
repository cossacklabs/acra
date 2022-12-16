See a verbose explanation of how to prepare environment and use the examples in [https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker/](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker/). The explanation is provided for Python, some minor tweaks might be needed to get Acra examples run with PHP.

These examples are simple as it may be with hardcoded values (sorry) just to see how you should create acrastructs and see decrypted data from database. Script will do next: encrypt data, save to database, fetch from database and print.
  
You can override next values in script to adapt to your environment:
* `$message` - message that will be encrypted and saved to db
* `$key_path` - path to file with storage public key that will be used to create acrastruct
* `$dbconn` - replace host|port|dbname|user|password with your settings for PostgreSQL. Use AcraConnector's host:port to print decrypted data and database's host:port to print encrypted data

## Run
```
php examples/php/example.php
```