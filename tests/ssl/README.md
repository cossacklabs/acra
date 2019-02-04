SSL folder contains all TLS keys that used in tests and must use databases used in tests

To create database with docker with correct keys, use dockerfiles from tests/docker which copies
keys from tests/ssl to correct paths in images

To re-generate keys (existing keys expires at 2069 year):
```
bash tests/ssl/generate_tls_keys.sh
```
Script will create tests/ssl/ca|acra-server|acra-writer|mysql|postgresql folders and place there keys
If you want to change output dir than change value of `OUT_DIR` variable in tests/ssl/generate_tls_keys.sh and re-run
