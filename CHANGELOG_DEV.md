# 0.94.0 - 2023-01-24
- Remove testing on the old versions of golang, leave only last fresh version

# 0.94.0 - 2023-01-11
- Extend `acra-keys` `destroy` tools with all key types destruction support;

# 0.94.0 - 2023-01-11
- Improved TLS configuration, `tls_ocsp_*` and `tls_crl_*` applied for TLS connections without `tls_ocsp_[client|database]_*`/`tls_crl_[client|database]_*` flags.g

# 0.94.0 - 2022-10-18
- Extend SQL syntax for searchable encryption with support JOINs query. 

# 0.94.0 - 2022-10-13
- Improve handling binary format of prepared statements for PostgreSQL with null values in Bind packets.

# 0.94.0 - 2022-10-05
- Refactored integration tests. Improved finalizing socket connections in AsyncpgExecutor. Allow to run tests with databases accessible via domain name not only localhost.
- Added additional certificates for integration tests in buildbot runner.

# 0.94.0 - 2022-09-21
- Extended SQL syntax for searchable encryption for PostgreSQL/MySQL with UPDATE/DELETE/INSERTS queries.

# 0.94.0 - 2022-09-21
- Implemented searchable tokenization for PostgreSQL/MySQL for text/binary protocols

# 0.94.0 - 2022-09-19
- Accumulate packets in a queue and handle paired packets in the correct order. Fixes issue with incorrectly linked Bind packet to inappropriate Parse packet and nil dereferences.

# 0.94.0 - 2022-08-25
- Add support of Hashicorp Consul for `encryptor_config loading`. 
- Introduce new Hashicorp Consul flags: `consul_connection_api_string` and `consul_kv_config_path` and corresponded `consul` TLS configuration flags.

# 0.94.0 - 2022-08-18
- Removed deprecated `--tls_db_sni` flag. Now only `--tls_database_sni` is available.
- Added additional TLS parameters related to OCSP/CRL for connections between App<->AcraServer<->Database:
  - CRL: `--tls_crl_client_cache_size`, `--tls_crl_client_cache_time`, `--tls_crl_client_check_only_leaf_certificate`, `--tls_crl_client_from_cert`, `--tls_crl_database_cache_size`, `--tls_crl_database_cache_time`, `--tls_crl_database_check_only_leaf_certificate`, `--tls_crl_database_from_cert`, `--tls_ocsp_client_check_only_leaf_certificate`
  - OCSP: `--tls_ocsp_client_check_only_leaf_certificate`, `--tls_ocsp_client_from_cert`, `--tls_ocsp_client_required`, `--tls_ocsp_database_check_only_leaf_certificate`, `--tls_ocsp_database_from_cert`, `--tls_ocsp_database_required`
- Updated `go` version in `go.mod` to 1.17.
- Replace `os.Setenv` with `t.Setenv` in tests.
- Replace `ioutil.TempDir` with `t.TempDir` in tests.

# 0.94.0 - 2022-08-03
- Fixed reloading on SIGHUP signal
- Implement KMS Keystore encryptor
- Extend `acra-keymaker`, `acra-addzone` and `acra-poisonrecord` tools with ability to create key encryption keys on KMS
- Introduce new flag `keystore_encryption_type` for all keystore related acra tools

# 0.94.0 - 2022-07-08
- Extend encryptor config struct with database settings section
  - Has subsections for mysql-specific settings as well as for postgres-specific ones
- Change in parser to properly extract quoted identifiers in PostgreSQL queries
- Table/column matching logic is slightly changed to better match what DMBS does

# 0.94.0 - 2022-07-01
- Refactor HTTP API and bring TLS to it

# 0.93.0 - 2022-06-15
- Add searchable encryption demo

# 0.93.0 - 2022-05-23
- Add support for mysql `_binary` charset.
- Handle properly null values in MySQL

# 0.93.0 - 2022-05-20
- Fix normalization of integers during an insertion.

# 0.93.0 - 2022-05-19
- Replace OID in Parse packets, if they are specified.

# 0.93.0 - 2022-05-18
- Reset placeholders in a connection state after `ReadyForQuery` packet.

# 0.93.0 - 2022-05-17
- Don't register prepared statements twice.

# 0.93.0 - 2022-05-13
- Don't abort connection of postgres after encoding error.

# 0.93.0 - 2022-05-10
- Don't abort connection of mysql after encoding error.

# 0.93.0 - 2022-05-04
- Add mysql support for `response_on_fail` options.

# 0.93.0 - 2022-04-20
- Add `make install_dev_deps` for development dependencies installation.

# 0.93.0 - 2022-04-19
- Fix output of `acra-keys list` for keystore v1: record duplication and wrong client id for log key.

# 0.93.0 - 2022-04-14
- Deprecate `tokenized` option and use non-empty `token_type` to indicate tokenization.
- Fix processing of a plain startup message after the `ssl deny`.

# 0.93.0 - 2022-04-07
- Extend config with `on_fail` field, which indicates wheter to return error ("error") to a client, or default values ("default") in case of error.

## 0.93.0 - 2022-04-06
- MySQL transparent decryption with replacing type's metadata
- Refactored MySQL internal data encoding/decoding structure by implementing separate `DataDecoderProcessor` and `DataEncoderProcessor`

## 0.93.0 - 2022-03-28
- Transparent decryption with replacing type's metadata
- Extend `encryptor_config` with new settings: `data_type=[int32|int64|str|bytes]` and `default_data_value: <SQL int literal | string | base64 string>`
- Support values in text format from Postgresql's binary protocol
- Refactored internals of data encoding/decoding, protocol processing, saving session related data

## 0.93.0 - 2022-03-23
- Remove autogeneration of poison keys on the first access (but keep in poisonrecordmaker).
- Add warning on enabled poison detection if keys are not generated.

## 0.93.0 - 2022-03-15
- Remove legacy flags dedicated to acra-connector from dockerfiles under the `./docker/` directory.

## 0.93.0 - 2022-03-12
- Fix postgres packet parser to raise error on unknown startup message.

## 0.93.0 - 2022-03-10
- Fix bug with PostgreSQL + prepared statements that was discovered while using Rust `postgres` crate

## 0.93.0 - 2022-03-10
- Remove `IsForbidden` field from acra-censor’s logs

## 0.92.0 - 2022-02-21
- Adapt python integration tests for python3.6 for tests on centos 7/8

## 0.92.0 - 2022-02-17
- Extend KeyStore interface to allow fetching single latest symmetric key for encryption purposes

## 0.92.0 - 2022-02-16
- Added cache keystore keys on start logic with `keystore_cache_on_start_enable` flag;
- Changed the default flag value for `keystore_cache_size` flag. Default is 1000;
- Added server halt for keystore `v2` and `keystore_cache_size` not -1;
- Cache fetching rotated key filenames to decrease extra syscalls

## 0.92.0 - 2022-02-14
- Add new script `run_transparent.sh` to `benchmark` folder that collects data from debug server for `pprof` tool and
  works with docker-compose file

## 0.92.0 - 2022-02-09
- Log messages that suggests how to fix problems related to TLS connection issues.

## 0.92.0 - 2022-02-04
- Cache symmetric keys in in-memory cache (if turned on) in same way as asymmetric
- Improved hash extraction with working searchable encryption. Now it will not try to get encrypted HMAC key from a keystore
  if matched valid hash header and remain data payload not matched to any CryptoEnvelope
- Avoid race conditions on startup when register listeners in `SServer` object
- Remove confusing logs about failed decryption after poison record checks in valid cases
- Changed log level for couple of confusing log events from Warning/Error to Debug because they don’t represent error
  cases and useful only for debugging
- Removed extra subscription of decryptor on every CryptoEnvelope when poison record detection turned on
- Speed up integration tests:
  - Fork openssl and CRL servers at module level once instead of forking on every test case
  - Allow to re-use already compiled binaries instead of compiling them on every test run. Same for `configs/regenerate.sh`
- Speed up CircleCI tests: build and cache acra binaries for each go version and after that run test jobs
- Updated Themis SecureCell API usage from old deprecated to new in `acrablock` package
- Removed unused legacy code in `acrablock` package left after migrating to `CryptoEnvelopes`
- Clarified log message for `AcraTranslator's` `DecryptSymSearchable` method

## 0.92.0 - 2022-02-02
- Change the default value for flag `--poison_detect_enable` from `true` to `false` for `acra-server` and `acra-translator`.
- Add integration tests for `acra-translator` with poison record detection and refactored poison record tests.
- Change the default port for prometheus handler in integration tests to fix port collisions during local testing.
- Use AcraBlocks as default crypto envelope;
- `acra-keymaker` fix ability to generate sym key into uncreated dir via `generate_symmetric_storage_key` flag;

## 0.92.0 - 2022-02-01
- `acra-connector` global removing from all its related components `acra-server`/`acra-translator`/`acra-keymaker`/`acra-keys`:
  - updated `acra-server` to use TLS as default connection configuration/ Themis Secure Session connection support removal/
    set `tls_client_id_from_cert=true` flag by default/ full usage removing of transport keys;
  - updated `acra-translator` to use TLS as default connection configuration;
  - updated `acra-keys` `read`, `generate`, `destroy` commands not to work with transport keys;
- refactor all integration tests to use TLS by default;

## 0.92.0 - 2022-01-20
- Improve TLS certificate validation performance with larger CRLs, check is now O(1) ops instead of O(N)

## 0.92.0 - 2022-01-18
- Improve acra-censor, remove infinite empty loop in `querycapture` handler

## 0.92.0 - 2021-12-29
- Improve sqlparser, support `null::text` type casts and avoid panics.

## 0.92.0 - 2021-12-22
- Extend python examples, add mysql support
- Generate certificates with service names as additional SAN for docker-compose files. Extend bash script to support several
  SAN values.

## 0.91.0 - 2021-12-15
### Deprecated
- `acra-connector` - deprecated and will be removed in next releases. All related flags in
  `acra-server`/`acra-translator`/`acra-keymaker` deprecated too and will be removed in next releases.
- `acra-server` CLI parameters: `--securesession_id`, `--acraconnector_tls_transport_enable`, `--acraconnector_transport_encryption_disable`
- `acra-keymaker` CLI parameters: `--generate_acraconnector_keys`, `--generate_acraserver_keys`, `--generate_acratranslator_keys`
- `acra-translator` CLI parameters: `--securesession_id`, `--acraconnector_transport_encryption_disable`, `--acratranslator_tls_transport_enable`
- `acra-keys` CLI parameters for `generate` command: `--acraconnector_transport_key`, `--acraserver_transport_key`, `--acratranslator_transport_key`

## 0.91.0 - 2021-12-13
### Changed
- updated `acra-keys` `read` to support work with symmetric storage keys;
- extend `acra-keys` `generate` with `zone_symmetric_key` flag to support rotating zone symmetric keys

## 0.91.0 - 2021-12-01
### Changed
- wrap `acra-censor`’s query writers’ manipulations of cached queries with a mutex to avoid race conditions
- tests run with `-race` flag to detect race conditions
- changed BoltDB dependency from old `github.com/boltdb/boltdb` to `go.etcd.io/bbolt` that doesn’t have race condition
  issues related to updated memory checks in go1.14

## 0.91.0 - 2021-11-29
### Changed
- `acra-translator`’s HTTP API methods support `POST` method additionally to `GET`. `GET` method is marked as deprecated
  and log the warning about it.

## 0.91.0 - 2021-11-25
### Changed
- `acra-censor's` query writer now can track amount of skipped queries and allows configuration of serialization
  frequency for tests. Fixed flaky tests related to not flushed data to a file before read.
- Reduced time of tests by:
  - removing redundant cache deletion
  - building base docker image with pre-downloaded golang dependencies
  - increasing serialization frequency and decreasing `time.Sleep` time in `acra-censor's` tests

## 0.91.0 - 2021-11-12
### Removed
- `acra-webconfig` package, related dockerfiles, updated docker-compose files.
- `acra-authmanager`.
- `--generate_acrawebconfig_keys` flag from `acra-keymaker`.
- `--acrawebconfig_symmetric_key` flag from `acra-keys generate` command.
- `--auth_keys` parameter from `acra-server`.
- `/loadAuthData`, `/getConfig`, `/setConfig` endpoints from `acra-server`’s HTTP API.
- `WebConfigKeyStore` interface and all implementations from `keystore` package (v1 and v2).
- Updated integration tests to run with Redis/added the ability of configurable run of integration tests with Redis
  via `TEST_REDIS` env

## 0.90.0 - 2021-11-10
### Changed
- Golang’s test `keystore/keyloader/hashicorp/vault_loader_test.go` runs with tags `--tags=integration,vault` with
  dependency on running external Vault instance
- .circleci/check_gotest.sh runs integration tests with Redis, Vault and BoltDB using `--tags=integration,redis,vault,boltdb`
  and expects running Vault and Redis
- actualize docker-compose files from `docker` directory with new Docker images/updated `acra-build` Dockerfile to build all Acra
  binaries with `netgo` resolver

## 0.85.0 - 2021-04-30
### Added
- Transparent searchable encryption with AcraBlocks as crypto envelope
- Transparent masking with AcraBlocks as crypto envelope
- Improved encryptor config validation
- Extended acra-keys with new command `extract-client-id` that return ClientID according to TLS certificate data

## 0.85.0 - 2021-03-11
### Added
- Generation keys by acra-keymaker by providing TLS certificate instead specific client_id. Added new CLI parameters:
  - `tls_identifier_extractor_type` - identifier extractor type which will use to extract client_id from TLS certificate
  - `tls_cert` - path to TLS certificate which metadata will be used as keys identifier

### Changed
- Allow empty SQL queries for binary protocols

## 0.85.0 - 2020-12-17

- Implemented support of TLS certificate validation using OCSP and CRL (Certificate Revocation Lists)
- New configuration options were added to AcraServer and AcraConnector:
  - OCSP-related:
    - `tls_ocsp_url`, `tls_ocsp_client_url`, `tls_ocsp_database_url` - URL of OCSP server to use, for AcraServer may be configured separately for both directions
    - `tls_ocsp_required` - whether to allow “unknown” responses, whether to query all known OCSP servers (including those from certificate)
    - `tls_ocsp_from_cert` - how to treat URL listed in certificate (use or ignore, whether to prioritize over configured URL)
    - `tls_ocsp_check_only_leaf_certificate` - whether to stop validation after checking first certificate in chain (the one used for TLS handshake)
  - CRL-related:
    - `tls_crl_url`, `tls_crl_client_url`, `tls_crl_database_url` - URL of CRL distribution point to use, for AcraServer may be configured separately for both directions
    - `tls_crl_from_cert` - how to treat URL listed in certificate (use or ignore, whether to prioritize over configured URL)
    - `tls_crl_check_only_leaf_certificate` - whether to stop validation after checking first certificate in chain (the one used for TLS handshake)
    - `tls_crl_cache_size` - how many CRLs to cache in memory
    - `tls_crl_cache_time` - how long cached CRL is considered valid and won’t be re-fetched

## 0.85.0 - 2020-12-08

- Extended TLS support and mapping to clientID for client’s key selection purposes
  - Strategy of extraction metadata from certificates for mapping to clientID: `tls_identifier_extractor_type` (default: `distinguished_name`, another option: `serial_number`)
  - Switching to new mode with clientID extraction from certificates: `tls_client_id_from_cert`

## 0.85.0 - 2020-09-28

### Added

- More specific TLS configuration options that allow to configure separate TLS settings between client app and AcraServer, and between AcraServer and database:
  - AcraServer certificate: `tls_client_cert` and `tls_database_cert` (override `tls_cert`)
  - AcraServer key: `tls_client_key` and `tls_database_key` (override `tls_key`)
  - CA certificate path: `tls_client_ca` and `tls_database_ca` (override `tls_ca`)
  - TLS authentication: `tls_client_auth` and `tls_database_auth` (override `tls_auth`)
- Renamed database SNI option: `tls_db_sni` => `tls_database_sni`

## 0.85.0 - 2020-04-02
### Added
- Support of RHEL >= 7
- Configurable build and install parameters in Makefile (see `make help`)
- Self-documented Makefile
- `go_install.sh` script
- Makefile `pkg` target with automatic detection of OS (use it instead of `rpm` and `deb`)
### Changed
- Build image use Debian 10 instead of Debian 9
- Application names in Docker image description got `CE` suffix
- Refined logic of automatic image tagging
### Removed
- Makefile targets `dist`, `temp_copy`
- `docker_push` target replaced with `docker-push`
- default argument `--db_host=postgres` from `acra-server` docker image, specifying it explicitly is more secure
- default argument `--acraserver_connection_host=acra-server` from `acra-connector` image
### Deprecated
- `docker` target in Makefile (will be removed in 0.87.0), use `docker-build` instead
- docker images `acra-authmanager` and `acra-keymaker` (will be removed in 0.87.0); all tools are now packaged into the `acra-tools` image
- Makefile targets `rpm` and `deb` are aliases for `pkg` and will be removed in future
