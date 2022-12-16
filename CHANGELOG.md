# Acra ChangeLog

## [0.94.0](https://github.com/cossacklabs/acra/releases/tag/0.94.0), November 16th 2022

_Core_:

In this release we deprecated [Zones functionality](https://docs.cossacklabs.com/acra/security-controls/zones/) and all flags and CLI parameters related to it. These flags will be removed in the next versions. Acra will warn about deprecations.
Acra Community Edition supports separate encryption keys linked to the `ClientIDs` and allows to manage key switching via [TLS certificates](https://docs.cossacklabs.com/acra/guides/integrating-acra-server-into-infrastructure/client_id/#tls-certificate).
[Acra Enterprise Edition](https://docs.cossacklabs.com/acra/enterprise-edition/) supports more flexible mapping between users/apps and encryption keys via [SQL variables](https://docs.cossacklabs.com/acra/security-controls/client-id-sql-detection/).

- **AcraServer, AcraTranslator, AcraKeymaker, AcraKeys, AcraRotate, AcraAddZone, AcraBackup, AcraLogVerifier, AcraPoisonRecordMaker, AcraRollback**:
  - Added new CLI flags for better KMS support ([documentation page](https://docs.cossacklabs.com/acra/configuring-maintaining/key-storing/kms-integration/#aws-kms), [#552](https://github.com/cossacklabs/acra/pull/552), [#553](https://github.com/cossacklabs/acra/pull/553), [#554](https://github.com/cossacklabs/acra/pull/554)):
    - `--kms_credentials_path=<filepath>` - path to configuration file specific for KMS type
    - `--kms_type=[aws]` - type of KMS provider
  - Added support of encrypting the Acra Master Key using AWS KMS key (key wrapping technique). [AWS KMS documentation page](https://docs.cossacklabs.com/acra/configuring-maintaining/key-storing/kms-integration/#aws-kms), [#552](https://github.com/cossacklabs/acra/pull/552).
  - Added support of the several encryption strategies for keys in the keystore ([#556](https://github.com/cossacklabs/acra/pull/556)) and added new CLI flag:
      - `--keystore_encryption_type` - specifies type of keys encryption for keystore. Accepts `env_master_key`, `vault_master_key`, `kms_encrypted_master_key`, `kms_per_client`. Read description of types on documentation pages of appropriate tools, for example [AcraKeymaker](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/acra-keymaker/#keystore).
  - Extended configuration of TLS options when storing ACRA_MASTER_KEY in HashiCorp Vault. [#578](https://github.com/cossacklabs/acra/pull/578)
  - Added 12 flags related to OCSP/CRL support. You can find all of these flags in documentation on pages related to appropriate tool, for example [AcraKeymaker](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/acra-keymaker/#hashicorp-vault). 
- **AcraServer, AcraTranslator, AcraKeymaker, AcraKeys, AcraRotate, AcraAddZone, AcraTokens**:
  - Added TLS support for Redis storage for Keystore. Added new 15 CLI flags related to TLS configuration. Read more on appropriate tool's page, for example [AcraKeymaker](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/acra-keymaker/#redis). [#566](https://github.com/cossacklabs/acra/pull/566), [#565](https://github.com/cossacklabs/acra/pull/565)
- **AcraServer, AcraTranslator, AcraKeymaker, AcraKeys, AcraRotate, AcraAddZone, AcraRollback**:
  - Deprecated all Zones related CLI flags and API descriptions [#577](https://github.com/cossacklabs/acra/pull/577)
- **AcraServer, AcraTranslator**:
  - Improved resistance against memory leakage: in-memory cache for keystore now uses randomly generated symmetric key for key encryption instead of ACRA_MASTER_KEY. [#555](https://github.com/cossacklabs/acra/pull/555)
  - Improved reloading on SIGHUP signals. [#557](https://github.com/cossacklabs/acra/pull/557)
- **AcraServer**: 
  - Added support of [HashiCorp Consul](https://www.consul.io/) as a configuration source for encryptor config. Acra can load configuration from the Consul instead of file. Added new CLI flag (`--encryptor_config_storage_type=[filesystem|consul]`) to switch source and Consul specific flags. Read more on [documentation page](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/acra-server/encryptor-config/) about encryptor config and acra-server's [configuration description](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/acra-server/#hashicorp-consul). [#568](https://github.com/cossacklabs/acra/pull/568)
  - Improved support of searchable tokenization. AcraServer captures `SELECT` queries and update `WHERE` clauses to add support of filtering with consistent tokenization. [#581](https://github.com/cossacklabs/acra/pull/581)
  - Improved searchable encryption with more complex queries. [#586](https://github.com/cossacklabs/acra/pull/586), [#592](https://github.com/cossacklabs/acra/pull/592), [#598](https://github.com/cossacklabs/acra/pull/598), [#599](https://github.com/cossacklabs/acra/pull/599), [#594](https://github.com/cossacklabs/acra/pull/594).
  - Improved SQL parser (better compatibility across different SQL databases):
    - Added support of `NULLS FIRST`/`NULLS LAST` ordering clauses, joins with subqueries [#547](https://github.com/cossacklabs/acra/pull/547)
    - Added support of `RETURNING` clauses. [#584](https://github.com/cossacklabs/acra/pull/584)
  - Improved processing prepared statement. [#580](https://github.com/cossacklabs/acra/pull/580), [#593](https://github.com/cossacklabs/acra/pull/593)
  - Added new section to encryptor config called `database_settings`. [#532](https://github.com/cossacklabs/acra/pull/532), [#590](https://github.com/cossacklabs/acra/pull/590)
    - Contains subsections `mysql` and `postgresql`
    - Currently `mysql` subsection has one option, `case_sensitive_table_identifiers`, boolean, to configure whether table names should be considered case-sensitive when comparing with names in encryptor config
  - Table/column matching now works like this:
    - For PostgreSQL:
      - Raw identifiers are case-insensitive
      - Identifiers wrapped with double quotes are case-sensitive
    - MySQL:
      - Column identifiers are always case-insensitive
      - Table names are case-insensitive by default, could be changed with `case_sensitive_table_identifiers` option mentioned above
    Case-insensitive means the identifier is converted to lowercase before comparing with values from encryptor config, encryptor config should contain lowercase version of column/table name.
    Case-sensitive means identifiers are compared with values from encryptor config "as is", encryptor config should contain exactly the same identifier as in database schema.
  - Removed deprecated `--tls_db_sni` flag. Now only `--tls_database_sni` is available. [#564](https://github.com/cossacklabs/acra/pull/564)
  - Added support of separate configuration and specifying of CRL/OCSP settings for connections from database and applications. Added flags: `--tls_ocsp_[database|client]_required`, `--tls_[ocsp|crl]_[database|client]_check_only_leaf_certificate`, `--tls_[ocsp|crl]_[database|client]_from_cert`, `--tls_[ocsp|crl]_[database|client}_cache_size`, `--tls_[ocsp|crl]_[database|client}_cache_time`, `--tls_[ocsp|crl]_[database|client}_cache_size`. You can find all of these flags in documentation on pages related to appropriate tool, for example [AcraServer](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/acra-server/#tls). [#564](https://github.com/cossacklabs/acra/pull/564). 
- **AcraTranslator**:
  - Improved HTTP API performance. Refactored HTTP processing core. Now AcraTranslator uses golang's [HTTP server](https://pkg.go.dev/net/http) with [gin](https://github.com/gin-gonic/gin) router [#550](https://github.com/cossacklabs/acra/pull/550). Added support of:
    - HTTP 2.0 connections additionally to HTTP 1.1
    - Keep alive connections
  - Added TLS support for HTTP API:
    - `--http_api_tls_transport_enable=[true|false]` new flag added to turn on accepting TLS connections instead of raw TCP. Works only together with  `--http_api_enable=true`. [#550](https://github.com/cossacklabs/acra/pull/550)

_Example projects and demos_:
- [Python examples](https://github.com/cossacklabs/acra/tree/0.94.0/examples/python): updated to show searchable encryption feature. [#548](https://github.com/cossacklabs/acra/pull/548)

## [0.93.0](https://github.com/cossacklabs/acra/releases/tag/0.93.0), May 27th 2022
This release brings type awareness which improves transparent encryption on AcraServer. Type awareness means that it's possible to tell AcraServer what are the original data types for fields. During decryption, AcraServer will convert decrypted fields to their original data types. No need to change client application code to work with "binary data".

It's also possible to choose a default value for each data field if its decryption failed. AcraServer can send a a default value like "<encrypted data>" instead of decryption errors, making developers' and users' life easier.

_Core_:

- **AcraServer**:
  - Added type awareness and ability to map binary data to a certain data type when sending decrypted data back to the application. Extended encryptor_config which allow configure mapping application data type to proper database's type. [#515](https://github.com/cossacklabs/acra/pull/515), [#517](https://github.com/cossacklabs/acra/pull/517), [#523](https://github.com/cossacklabs/acra/pull/523), [#519](https://github.com/cossacklabs/acra/pull/519), [#520](https://github.com/cossacklabs/acra/pull/520)
  - Extended `encryptor_config` with new parameters:
    - `data_type` - specify data type expected by application. Accept `str`, `bytes`, `int64`, `int32` values. [#515](https://github.com/cossacklabs/acra/pull/515), [#517](https://github.com/cossacklabs/acra/pull/517)
    - `default_data_value` - specify a placeholder (default value) to replace data that couldn't be decrypted. [#515](https://github.com/cossacklabs/acra/pull/515), [#517](https://github.com/cossacklabs/acra/pull/517)
    - `response_on_fail` - specify action on decryption failure. Accepts `ciphertext` (returns encrypted data as is), `default_value` (returns values from `default_data_value` parameter), `error` (returns error as DB error with message like `encoding error in column {column_name}`). [#521](https://github.com/cossacklabs/acra/pull/521), [#533](https://github.com/cossacklabs/acra/pull/533)
  -  Deprecated `tokenize` parameter in `encryptor_config` and changed focus on `token_type` parameter. Now is enough to specify `token_type` parameter without `tokenize: true` to turn on tokenization. [Read more](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/acra-server/encryptor-config/#tokenized-deprecated-since-0930) in the documentation. [#527](https://github.com/cossacklabs/acra/pull/527)
  - Removed auto-generation poison record's keys but leaved for `acra-poisonrecordmaker`. It improves decryption due to omitting extra key generation and poison record recognition. [#516](https://github.com/cossacklabs/acra/pull/516)
  - Improvements in handling error cases on DB protocol layer. [#511](https://github.com/cossacklabs/acra/pull/511), [#515](https://github.com/cossacklabs/acra/pull/515), [#517](https://github.com/cossacklabs/acra/pull/517), [#520](https://github.com/cossacklabs/acra/pull/520), [#528](https://github.com/cossacklabs/acra/pull/528), [#535](https://github.com/cossacklabs/acra/pull/535), [#537](https://github.com/cossacklabs/acra/pull/537)
  - Improved sql parser and support of `set` command. [#534](https://github.com/cossacklabs/acra/pull/534)
  - Ignored legacy keys on startup loading to cache. [#510](https://github.com/cossacklabs/acra/pull/510), [#522](https://github.com/cossacklabs/acra/pull/522)
  - Improved PostgreSQL/MySQL protocol support. [#525](https://github.com/cossacklabs/acra/pull/525), [#526](https://github.com/cossacklabs/acra/pull/526), [#539](https://github.com/cossacklabs/acra/pull/539), [#540](https://github.com/cossacklabs/acra/pull/540), [#541](https://github.com/cossacklabs/acra/pull/541), [#542](https://github.com/cossacklabs/acra/pull/542), [#543](https://github.com/cossacklabs/acra/pull/543), [#544](https://github.com/cossacklabs/acra/pull/544)
- **AcraCensor**:
  - Removed legacy `IsForbidden` field from acra-censor’s logs. [Read more here](https://docs.cossacklabs.com/acra/security-controls/sql-firewall/#logging-unique-queries) in notes. [#508](https://github.com/cossacklabs/acra/pull/508)
- **AcraKeys**:
  - Removed duplicate entries in `list` command. [#530](https://github.com/cossacklabs/acra/pull/530)
- **Other**:
  - Makefile target `install_dev_deps` install required golang's dependencies for development and code generation. [#531](https://github.com/cossacklabs/acra/pull/531)

_Documentation_:
- Improved description of AcraServer's [encryptor_config](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/acra-server/encryptor-config/), adding details and examples about data processing options: encryption, searchable encryption, masking, tokenization, type awareness, etc.
- Updated ["Debugging and troubleshooting"](https://docs.cossacklabs.com/acra/configuring-maintaining/debugging-and-troubleshooting/) section with more tips and tricks. 

_Example projects and demos_:
- [Python examples](https://github.com/cossacklabs/acra/tree/0.93.0/examples/python): updated to show type masking feature. [#524](https://github.com/cossacklabs/acra/pull/524), [#529](https://github.com/cossacklabs/acra/pull/529)
- [acra-engineering-demo](https://github.com/cossacklabs/acra-engineering-demo/tree/0.93.0) updated to show data type masking support. [#46](https://github.com/cossacklabs/acra-engineering-demo/pull/46), [#47](https://github.com/cossacklabs/acra-engineering-demo/pull/47), [#48](https://github.com/cossacklabs/acra-engineering-demo/pull/48), [#49](https://github.com/cossacklabs/acra-engineering-demo/pull/49), [#50](https://github.com/cossacklabs/acra-engineering-demo/pull/50), [#51](https://github.com/cossacklabs/acra-engineering-demo/pull/51).

## [0.92.0](https://github.com/cossacklabs/acra/releases/tag/0.92.0), March 01th 2022

This release brings stability and performance fixes to AcraServer and AcraTranslator. It officially deprecates usage 
of AcraConnector in favour of TLS everywhere. Some default configuration params are changed in favour of more secure & 
better performance settings.

_Core_:
- **AcraServer, AcraTranslator**:
  - Improved TLS certificate validation performance with CRL. [#482](https://github.com/cossacklabs/acra/pull/482)
  - Poison record detection turned off by default. Flag `--poison_detect_enable` changed default value from `true` to `false`. [#484](https://github.com/cossacklabs/acra/pull/484)
  - Removed SecureSession and AcraConnector support as transport encryption. [#481](https://github.com/cossacklabs/acra/pull/481)
  - Improved and clarified log messages. Removed messages with `error` level for success cases (not detected poison record),
    clarified context of messages. [#487](https://github.com/cossacklabs/acra/pull/487)
  - Added suggestions in log messages how to solve issues with TLS connections. [#493](https://github.com/cossacklabs/acra/pull/493)
  - Improved in-memory caching keys:
    - Added caching symmetric keys like asymmetric [#489](https://github.com/cossacklabs/acra/pull/489)
    - Added caching metadata about rotated keys [#498](https://github.com/cossacklabs/acra/pull/498)
    - Added new flag `--keystore_cache_on_start_enable` that turns on loading all keys into in-memory cache on startup. [#497](https://github.com/cossacklabs/acra/pull/497)
    - Changed default value for `--keystore_cache_size` parameter from `-1` (which means no limits for cache) to 1000 (cache items). [#497](https://github.com/cossacklabs/acra/pull/497)
    - Legacy keys that were used with AcraConnector are now ignored during initial caching on startup. [#510](https://github.com/cossacklabs/acra/pull/510)
- **AcraServer**:
  - The default CryptoEnvelope has changed from `acrastruct` to `acrablock` in the encryptor_config. Now AcraServer 
    will use faster encryption by default. You can select which CryptoEnvelope to use in encryptor_config. 
    See [AcraStructs vs AcraBlocks documentation](https://docs.cossacklabs.com/acra/configuring-maintaining/optimizations/acrastructs_vs_acrablocks/), [#485](https://github.com/cossacklabs/acra/pull/485)
  - Extended PostgreSQL's SQL syntax support with `null::<type>` type casts. [#479](https://github.com/cossacklabs/acra/pull/479)
  - Changed the default values for next CLI parameters:
    - `--tls_client_id_from_cert` changed from `false` to `true`. Now AcraServer require app's TLS certificates and map them to keys. [#481](https://github.com/cossacklabs/acra/pull/481)
  - Improved performance for:
    - `querycapture` handler in AcraCensor. [#483](https://github.com/cossacklabs/acra/pull/483)
    - transparent encryption and poison record detection. [#487](https://github.com/cossacklabs/acra/pull/487), [#496](https://github.com/cossacklabs/acra/pull/496)
    - searchable encryption. [#490](https://github.com/cossacklabs/acra/pull/490)
  - Removed next CLI parameters due to removed AcraConnector support:
    - `--securesession_id`, `--acraconnector_tls_transport_enable`, `--acraconnector_transport_encryption_disable`. [#481](https://github.com/cossacklabs/acra/pull/481)
- **AcraTranslator**:
  Now AcraTranslator works with TLS by default, it doesn't support AcraConnector anymore. [#481](https://github.com/cossacklabs/acra/pull/481)
  - Removed next CLI parameters due to removed AcraConnector support:
    - `--securesession_id`, `--acratranslator_tls_transport_enable`, `--acraconnector_transport_encryption_disable`. [#481](https://github.com/cossacklabs/acra/pull/481) 
- **AcraKeymaker**:
  - Now handle correctly generation symmetric keys into not existing folders. [#486](https://github.com/cossacklabs/acra/pull/486)
  - Removed next CLI parameters due to removed AcraConnector support:
    - `--generate_acraconnector_keys`, `--generate_acraserver_keys`, `--generate_acratranslator_keys`. [#481](https://github.com/cossacklabs/acra/pull/481)
- **AcraKeys**:
  - Removed next key types for all commands (generate, read, destroy): `transport-connector`, `transport-server`, `transport-translator`. [#481](https://github.com/cossacklabs/acra/pull/481)
- **AcraConnector**:
  - Removed everywhere and stopped support. Switch to TLS instead, see [Security controls > Transport Security > TLS](https://docs.cossacklabs.com/acra/security-controls/transport-security/tls/), [#481](https://github.com/cossacklabs/acra/pull/481)

_Example projects and demos_:
- [Python examples](https://github.com/cossacklabs/acra/tree/0.91.0/examples/python): now support MySQL database. [#476](https://github.com/cossacklabs/acra/pull/476)
 

## [0.91.0](https://github.com/cossacklabs/acra/releases/tag/0.91.0), December 16th 2021

_Core_:
- **AcraWebConfig, AcraAuthManager**:
  - Have been deprecated and not supported anymore [#456](https://github.com/cossacklabs/acra/pull/456). The following changes have been made:
    - removed `docker/acra-authmanager.dockerfile`, `docker/acra-webconfig.dockerfile` files.
    - removed `acra-webconfig` and `acra-authmanager` from `docker/acra-build.dockerfile` file that is base image for all
      other service's images.
    - removed `acra-webconfig` and `acra-authmanager` from all `docker/docker-compose.*.yml` files.
    - reserved [event codes](https://github.com/cossacklabs/acra/blob/0.90.0/logging/event_codes.go#L64) for log entries in range [550, 558] related to AcraWebConfig.
- **AcraConnector**:
  - Has been deprecated and will be removed in the next releases. AcraServer and AcraTranslator will accept only direct TLS. See [Transport security/TLS](https://docs.cossacklabs.com/acra/security-controls/transport-security/tls/).
    connections from applications.
  - Removed mentions and usage from [acra-engineering-demo](https://github.com/cossacklabs/acra-engineering-demo/tree/0.90.0)s.
- **AcraKeymaker**:
  - Some keys can be configured without ClientID [#454](https://github.com/cossacklabs/acra/pull/454).
  - Removed `--generate_acrawebconfig_keys` flag according to AcraWebConfig/AcraAuthManager deprecation [#456](https://github.com/cossacklabs/acra/pull/456).
- **AcraKeys**:
  - `read` command supports symmetric encryption keys with ClientID and ZoneID [#472](https://github.com/cossacklabs/acra/pull/472/files).
  - `generate` command:
    - supports rotation for symmetric encryption keys with ZoneID [#472](https://github.com/cossacklabs/acra/pull/472/files).
    - deprecates next flags: `--acraconnector_transport_key`, `--acraserver_transport_key`, `--acratranslator_transport_key`.
    - removed `--acrawebconfig_symmetric_key` flag according to AcraWebConfig/AcraAuthManager deprecation [#456](https://github.com/cossacklabs/acra/pull/456).
  - Improved handling CLI parameters related to Redis [#459](https://github.com/cossacklabs/acra/pull/459).
- **AcraServer**:
  - Removed `--auth_keys` parameter according to AcraWebConfig/AcraAuthManager deprecation [#456](https://github.com/cossacklabs/acra/pull/456).
  - Removed `/loadAuthData`, `/getConfig`, `/setConfig` endpoints from HTTP API according to AcraWebConfig/AcraAuthManager deprecation [#456](https://github.com/cossacklabs/acra/pull/456).
- **AcraTranslator**:
  - Accepts `POST` HTTP request method additionally to `GET` for v2 API. Method `GET` marked as deprecated and warns with log message.
  `Deprecated HTTP GET method was used. Please use HTTP POST method instead.` if was used [#466](https://github.com/cossacklabs/acra/pull/466).

_Infrastructure_:
- Build binaries with `-tags netgo` flag, that forces usage of Go resolver to solve issues related to resolving hostnames. 
  between Docker containers. Updated `acra-build.dockerfile` used as base image for all `cossacklabs/acra-*` images ([#452](https://github.com/cossacklabs/acra/pull/452)).
- Added missing parameter `--keystore=v1` for existing docker-compose files that caused errors ([#452](https://github.com/cossacklabs/acra/pull/452)).

_Documentation_:
- Has been updated :)
- Improved guide about [integration AcraTranslator](https://docs.cossacklabs.com/acra/guides/integrating-acra-translator-into-new-infrastructure/) into infrastructure.
- Extended description for AcraTranslator's [HTTP API](https://docs.cossacklabs.com/acra/guides/integrating-acra-translator-into-new-infrastructure/http_api/).

_Example projects and demos_:
- [Python examples](https://github.com/cossacklabs/acra/tree/0.90.0/examples/python): now work with TLS connections to 
  AcraServer/Database. Also has been updated sqlalchemy version and binary column type from `Binary` to `LargeBinary` [#463](https://github.com/cossacklabs/acra/pull/463).
- [acra-engineering-demo](https://github.com/cossacklabs/acra-engineering-demo/tree/0.90.0)s don't illustrate AcraConnector usage anymore. All applications and services connect to AcraServer directly.

## [0.90.0](https://github.com/cossacklabs/acra/releases/tag/0.90.0), November 05th 2021

_New_:
- **Updated documentation:**
   
   Acra's documentation is now open-source and updated for this release. Please find use cases, usage scenarios, data flows, descriptions of security controls, cryptography deep dive, scaling and load balancing, optimisations and many more. 
   
   Check out [the updated documentation](https://docs.cossacklabs.com/acra/what-is-acra/).
- **Searchable encryption:**

  Two components can provide searchable encryption functionality:
  - **AcraServer** — transparent searchable encryption of fields marked as searchable in `encryptor_config` for `INSERT` and 
    `UPDATE` queries, calculating hash and searching by hash for `SELECT` queries, with per column configuration.
  - **AcraTranslator** — provides gRPC and HTTP API calls to encrypt data field into searchable form, and to generate 
    searchable hash from the plaintext search query.

  Read more details in the [Acra documentation](https://docs.cossacklabs.com/acra/security-controls/searchable-encryption/) 
  section dedicated to Searchable encryption.

- **Masking:**

- **AcraServer** – provides masking functionality. It is transparent masking for `INSERT` and `UPDATE` queries, and transparent demasking for `SELECT` queries, 
  with per column configuration.
  Read more details in the [Acra documentation](https://docs.cossacklabs.com/acra/security-controls/masking/)
  section dedicated to Masking.

- **Tokenization (Pseudonymisation):**

  Two components can provide tokenization functionality:
  - **AcraServer** — transparent tokenization for INSERT and UPDATE queries, and transparent detokenization for SELECT queries, with per column configuration.
  - **AcraTranslator** — provides gRPC and HTTP API to tokenize or detokenize the field.

  Read more details in the [Acra documentation](https://docs.cossacklabs.com/acra/security-controls/tokenization/)
  section dedicated to Tokenization.

- **AcraBlock:**

  AcraBlock is a symmetric cryptographic container and is faster and more compact than AcraStruct. It used on AcraServer side in 
  transparent encryption, masking, tokenization, searchable encryption. 
  
  AcraTranslator supports AcraBlocks in encryption, searchable encryption and tokenization via gRPC and HTTP API.

  Read more details in the [Acra documentation](https://docs.cossacklabs.com/acra/acra-in-depth/data-structures/acrablock/)
  section dedicated to AcraBlock.

- ** KeyStore v2**
  Added new storage format for keys in KeyStore that cryptographically strong key integrity checks,
  additional tracking metadata simplifying key management, KMS integrations.
  Read more details in the [Acra documentation](https://docs.cossacklabs.com/acra/security-controls/key-management/versions/)
  about difference between two versions.

- **HashiCorp Vault integration:**

  All Acra services that work with encryption/intermediate keys can load master key `ACRA_MASTER_KEY` from [HashiCorp Vault](https://www.vaultproject.io/). 
  Previously was supported only environment variables.

  Read more details on our [KMS integration](https://docs.cossacklabs.com/acra/configuring-maintaining/key-storing/kms-integration/) 
  page in the documentation.

_Core_:

- **AcraServer**:
  - We recommend using AcraServer in transparent encryption mode, connecting to it via TLS from application side. Use AcraServer with AcraBlocks for faster & more efficient configuration. AcraConnector and AcraWriter are optional components, and can be omitted.
  
  Read more details on our [Integrating AcraServer into infrastructure](https://docs.cossacklabs.com/acra/guides/integrating-acra-server-into-infrastructure/).

  - Added prepared statements support for MySQL. Now all transparent operations over the data works with prepared 
    statements too.
  - Extended and refactored TLS related CLI parameters.
    - `tls_client_id_from_cert` - switching to new mode with clientID extraction from certificates instead of handshakes
      with AcraConnector or static mode with `--client_id` parameter.
    - OCSP-related:
      - `tls_ocsp_url`, `tls_ocsp_client_url`, `tls_ocsp_database_url` - URL of OCSP server to use, for `acra-server` may be configured separately for both directions.
      - `tls_ocsp_required` - whether to allow "unknown" responses, whether to query all known OCSP servers (including those from certificate).
      - `tls_ocsp_from_cert` - how to treat URL listed in certificate (use or ignore, whether to prioritize over configured URL).
      - `tls_ocsp_check_only_leaf_certificate` - whether to stop validation after checking first certificate in chain (the one used for TLS handshake).
    - CRL-related:
      - `tls_crl_url`, `tls_crl_client_url`, `tls_crl_database_url` - URL of CRL distribution point to use, for `acra-server` may be configured separately for both directions.
      - `tls_crl_from_cert` - how to treat URL listed in certificate (use or ignore, whether to prioritize over configured URL).
      - `tls_crl_check_only_leaf_certificate` - whether to stop validation after checking first certificate in chain (the one used for TLS handshake).
      - `tls_crl_cache_size` - how many CRLs to cache in memory.
      - `tls_crl_cache_time` - how long cached CRL is considered valid and won't be re-fetched.

    Separated parameters for connections accepted from application/AcraConnector or established to database with TLS:
      - `acra-server`'s certificate: `tls_client_cert` and `tls_database_cert` (overrides `tls_cert`).
      - `acra-server`'s key: `tls_client_key` and `tls_database_key` (overrides `tls_key`).
      - CA certificate path: `tls_client_ca` and `tls_database_ca` (overrides `tls_ca`).
      - TLS authentication: `tls_client_auth` and `tls_database_auth` (overrides `tls_auth`).
  - Supports `RETURNING` syntax in SQL queries with proper decryption data in the response.
  - `--sql_parse_on_error_exit_enable` new flag that force `acra-server` to stop query execution if can't parse SQL query. 
    By default, it is `false`.
  - Improved encryptor config validation.
  - **Deprecated** `--acrastruct_wholecell_enable` and `--acrastruct_injectedcell_enable` flags and will be ignored. 
    Now `acra-server` works as in InjectedCell mode.
  - **Deprecated** `--tls_db_sni` parameter and replaced with `tls_database_sni`.

- **AcraTranslator**:

  - We recommend using AcraTranslator as gRPC or HTTP API, connecting to it via TLS from application side. Use AcraTranslator with AcraBlocks for faster & more efficient configuration. 
  
  Read more details on our [Integrating AcraTranslator into infrastructure](https://docs.cossacklabs.com/acra/guides/integrating-acra-translator-into-new-infrastructure/).
  - `--acratranslator_client_id_from_connection_enable` flag turns on mapping TLS certificates to encryption keys with .
  - Extended HTTP API as version 2 and gRPC API with supporting all new features like Searchable encryption, Tokenization, 
    symmetric key encryption with AcraBLock and synchronized with gRPC API.
  - HTTP API version 2 with OpenAPI and Swagger support.

- **AcraServer, AcraTranslator**
  - `audit_log_enable` - new parameter turns on cryptographically signed audit logging. Read more in the 
    [Acra documentation](https://docs.cossacklabs.com/acra/security-controls/security-logging-and-events/audit-logging/).
  - Support direct TLS connections from applications without AcraConnector. `acra-server` and `acra-translator` will map
    client's certificates to proper encryption keys in KeyStore. 
  - `tls_identifier_extractor_type` - new parameter that configures strategy of extraction metadata from certificates for mapping to clientID
    (default: `distinguished_name`, another option: `serial_number`).

- **AcraServer, AcraTranslator, AcraConnector**
  - TLS certificate validation using OCSP and CRL. All services and tools that accepts incoming connections can be configured
    with new rules of connection validation.
    Read more details in the [Acra documentation](https://docs.cossacklabs.com/acra/configuring-maintaining/tls/)
    section dedicated to TLS configuration.
  - `--log_to_console` - parameter turns on\off logging to stderr.
  - `--log_to_file` - parameter specify path to file for logs. May be used together with logging to stderr.

- **AcraKeymaker**
  New flags to generate new kind of keys for new features:
  - `--generate_hmac_key` - flag turns on generation symmetric key for HMAC used in searchable encryption.
  - `--generate_log_key` - flag turns on generation symmetric key for cryptographically signed audit logging.
  - `--generate_symmetric_storage_key` - flag turns on generation symmetric key for encryption with AcraBlocks.
  - `--keystore` - specify version of KeyStore. Now supported `v1` (default) and `v2` (new) versions.

  New flags to generate encryption keys for TLS certificates:
  - `--tls_cert` - specify client's TLS certificate to generate encryption keys. Should be used instead `--client_id` flag.
  - `--tls_identifier_extractor_type` - switch type of ClientID extraction from TLS certificate. Supports 
    `distinguished_name` (default) and `serial_number` values.

- **AcraAddZone**
  - `--fs_keystore_enable` now is deprecated and ignored.

- **AcraTokens**
  `acra-tokens` is a new command-line utility used for managing generated tokens with turned on tokenization. Tokens may be stored in BoltDB or Redis for now.
  Read more details in the [Acra documentation](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/acra-tokens/).

- **AcraBackup**
  `acra-backup` is a command-line utility used for storing and managing the keystore backups. Also, it helps to migrate
  keys from one KeyStore to another one by `export` + `import` operations.
  Read more details in the Acra documentation on [acra-backup page](https://docs.cossacklabs.com/acra/configuring-maintaining/general-configuration/acra-backup/).

- **AcraKeys**
  `acra-keys` is a command-line utility used for different keys operations especially for v2 keystore. It consists of 
  several subcommands each of which is responsible for a separate functionality.

- **Other**
  - Support of RHEL >= 7
  - Build image use Debian 10 instead of Debian 9
  - Configurable build and install parameters in Makefile (see `make help`)
  - Self-documented Makefile
  - Makefile `pkg` target with automatic detection of OS (use it instead of `rpm` and `deb`)
  - Makefile targets `dist`, `temp_copy`
  - `docker_push` target replaced with `docker-push`

## [0.85.0](https://github.com/cossacklabs/acra/releases/tag/0.85), March 15th 2018

_Core_:

- **Breaking changes:** 

  Introducing a new more flexible configuration format for AcraCensor rules. AcraCensor doesn't support the old format, all users should migrate (don't worry, it's a simple procedure).

- **Search through encrypted data**

  You now can run SQL queries over encrypted AcraStructs allowing users to search through sensitive data without exposing it. This feature is only available in [Acra Enterprise version](https://www.cossacklabs.com/acra/#pricing).

- **Transparent proxy mode**

  _TLDR:_ Transparent proxy mode allows you to configure AcraServer to encrypt records in specific database columns without altering the application code.

  The application flow doesn't need to change: application sends SQL requests through AcraConnector and AcraServer to the database. AcraServer parses each request, encrypts the desired values into AcraStructs, and passes the modified requests to the database. To retrieve the decrypted data, your application talks to AcraServer again: upon receiving the database response, AcraServer tries to detect AcraStructs, decrypts them, and returns the decrypted data to the application.

  Transparent proxy mode is useful for large distributed applications where updating the source code of each client app separately would be complicated.

  To enable this mode, you need to create a separate encryptor configuration file (`acra-encryptor.yaml`) that describes which columns to encrypt and provide a path to it in the AcraServer configuration file (or via CLI params `--encryptor_config_file=acra-encryptor.yaml`).

  Read more details in the Readme and in the [Acra documentation](https://docs.cossacklabs.com/products/acra/) section dedicated to Transparent encryption.

  ([#285](https://github.com/cossacklabs/acra/pull/285), [#309](https://github.com/cossacklabs/acra/pull/309), [#314](https://github.com/cossacklabs/acra/pull/314)).

- **AcraCensor – SQL firewall to prevent SQL injections**
  
  _TLDR:_ Improved stability of AcraCensor, switched to more flexible rules' configuration.

  _Breaking changes:_ Introducing a new format for configuration files, the previous format is no longer supported, you should migrate to the new one.
  
  - New configuration file format allows configuring the allowlist and the denylist separately or simultaneously.
  
    The `allow` handler allows something specific and restricts/forbids everything else. The `allowall` handler should be a final statement as that means that all the other queries will be allowed.
    
    The `deny` handler allows everything and forbids something specific. The `denyall` means "block all queries!" (that haven't been allowed or ignored before).
    
    For each handler, there are settings that regulate queries, tables, and patterns. The order of priority for the lists is defined by their position in the configuration file. The processing priority for each list is as follows: queries, followed by tables, followed by patterns.
    
    ([#298](https://github.com/cossacklabs/acra/pull/298), [#297](https://github.com/cossacklabs/acra/pull/297), [#304](https://github.com/cossacklabs/acra/pull/304), [#306](https://github.com/cossacklabs/acra/pull/306)).
    
    Read more in [AcraCensor docs](https://docs.cossacklabs.com/pages/documentation-acra/#acracensor-acra-s-firewall).
  
  - Added version to the configuration file. This allows detecting an outdated configuration easily. From now on, AcraCensor supports explicit configuration version and logs errors if the configuration is not valid ([#321](https://github.com/cossacklabs/acra/pull/321)).

  - Improved parsing of SQL queries with prepared statements ([#303](https://github.com/cossacklabs/acra/pull/303), [#283](https://github.com/cossacklabs/acra/pull/283)).
  
  - Improved error handling for queries that AcraCensor can't parse ([#291](https://github.com/cossacklabs/acra/pull/291), [#284](https://github.com/cossacklabs/acra/pull/284)).

  - Added ability to log unparsed queries to a separate log file for the debugging and configuration purposes. Sometimes AcraCensor can't parse all of the incoming queries and it is useful to have a separate log for them. 
    
    How to use it: Provide the path to the unparsed queries log file in the configuration file `parse_errors_log: unparsed_queries.log` ([#295](https://github.com/cossacklabs/acra/pull/295)).

  - Improved support of PostgreSQL queries (`"RETURNING"` clause) and quoted identifiers (now you can use `"tablename"` and `WHERE "column"=1`) ([#296](https://github.com/cossacklabs/acra/pull/296)).

  - Fixed the bug in QueryCapture log that caused duplicated of records in the log to appear ([#318](https://github.com/cossacklabs/acra/pull/318)).

- **AcraServer**

  - Fixed handling of null-size packets in PostgreSQL protocol ([#286](https://github.com/cossacklabs/acra/pull/286)).

  - Fixed handling of setting a custom connection API port  ([#294](https://github.com/cossacklabs/acra/pull/294)).

  - Fixed handling of the plain text data response: if the database returns a plain text response, it is redirected "as is" ([#305](https://github.com/cossacklabs/acra/pull/305)).
  
  - Fixed handling of casted placeholders in expressions like `SELECT $1::type1::type2 FROM table1 WHERE column1=$2::type3::type4` ([#328](https://github.com/cossacklabs/acra/pull/328)).

  - Improved code quality (some refactoring here and there) ([#302](https://github.com/cossacklabs/acra/pull/302), [#301](https://github.com/cossacklabs/acra/pull/301)).

- **AcraServer, AcraTranslator, AcraConnector**

  - Refactored logs and error messages got even more descriptive and user-friendly ([#312](https://github.com/cossacklabs/acra/pull/312), [#299](https://github.com/cossacklabs/acra/pull/299), [#317](https://github.com/cossacklabs/acra/pull/317)).

  - Added on-start version logging to make it easier to understand which version is running ([#319](https://github.com/cossacklabs/acra/pull/319)).

  - Added versioning for configuration files of each service ([#322](https://github.com/cossacklabs/acra/pull/322)).

  - Added exporting version to metrics ([#330](https://github.com/cossacklabs/acra/pull/330), [#320](https://github.com/cossacklabs/acra/pull/320)).
  
  - Updated some configuration parameters descriptions for better user-friendliness (please see our docs of [AcraConnector](https://docs.cossacklabs.com/pages/documentation-acra/#changing-configuration-options-for-acraconnector) and [AcraServer](https://docs.cossacklabs.com/pages/documentation-acra/#acraserver-configuration-files) for detailed descriptions of each parameter and usage examples) ([#329](https://github.com/cossacklabs/acra/pull/329)).

- **AcraWriter**

  - Updated AcraWriter for ActiveRecord (Ruby), fixed dependencies, added support of mysql2 adapter ([#287](https://github.com/cossacklabs/acra/pull/287)).

  - Updated AcraWriter for Django (Python), fixed potential encoding issues ([#293](https://github.com/cossacklabs/acra/pull/293), [#292](https://github.com/cossacklabs/acra/pull/292)).

  - Updated AcraWriter for C++, improved cpp codec usage ([#290](https://github.com/cossacklabs/acra/pull/290), [#289](https://github.com/cossacklabs/acra/pull/289)).

  - Added bitcode for AcraWriter iOS and added Swift example project ([#327](https://github.com/cossacklabs/acra/pull/327), [#326](https://github.com/cossacklabs/acra/pull/326), [#325](https://github.com/cossacklabs/acra/pull/325), [#324](https://github.com/cossacklabs/acra/pull/324), [#323](https://github.com/cossacklabs/acra/pull/323), [#323](https://github.com/cossacklabs/acra/pull/323), [#307](https://github.com/cossacklabs/acra/pull/307)).

  - Improved distribution of AcraWriter for Android, now it's available via Maven ([#310](https://github.com/cossacklabs/acra/pull/310)).

- **Other**

  - Added more tests and then — added even more tests. We just love automating things! ([#331](https://github.com/cossacklabs/acra/pull/331), [#311](https://github.com/cossacklabs/acra/pull/311), [#308](https://github.com/cossacklabs/acra/pull/308), [#292](https://github.com/cossacklabs/acra/pull/292)).

  - Updated the version of pyyaml used in the tests due to [CVE-2017-18342](https://nvd.nist.gov/vuln/detail/CVE-2017-18342). This change doesn't affect the users of Acra, it only affects our test suite ([#300](https://github.com/cossacklabs/acra/pull/300)).


_Infrastructure_:

- Updated Docker files, added more comments, and updated Go version ([#313](https://github.com/cossacklabs/acra/pull/313), [#288](https://github.com/cossacklabs/acra/pull/288)).


_Example projects and demos_:

- [iOS Swift example project](https://github.com/cossacklabs/acra/tree/master/examples/swift) that shows how to generate AcraStructs with and without Zones.

- [Android example project](https://github.com/cossacklabs/acra/tree/master/examples/android_java) that shows how to integrate AcraWriter library into Android app using maven, and then to generate AcraStructs with and without Zones, and to decrypt them using AcraTranslator.

- [AcraCensor demo](https://github.com/cossacklabs/acra-censor-demo) that shows how to configure AcraCensor for SQL injections prevention in OWASP Mutillidae 2 example app.

- [Protecting data in a Rails application demo](https://github.com/cossacklabs/acra-engineering-demo#protecting-data-in-a-rails-application) based on AcraServer, PostgreSQL, and Ruby on Rails client application.

- [Protecting metrics in TimescaleDB demo](https://github.com/cossacklabs/acra-engineering-demo#protecting-metrics-in-timescaledb) based on AcraServer, TimescaleDB, and Grafana.

- [Transparent proxy mode demo](https://github.com/cossacklabs/acra-engineering-demo#protecting-data-on-django-based-web-site) that shows how to configure AcraServer in Transparent proxy mode to protect Django-based application.


_Related blog posts_:

- [The difference between SQL firewalls and Web Application Firewalls](https://www.cossacklabs.com/blog/sql-firewall-vs-waf-against-sqli.html).

- [Engineering details on how we built AcraCensor](https://www.cossacklabs.com/blog/how-to-build-sql-firewall-acracensor.html).


_Features coming soon_:

- Pseudonymisation: an early version of pseudonymisation library/plugin for Acra for transparent data pseudonymisation.

- Cryptographically protected audit log: protection for logs against tampering.


_Documentation_:

- Updated [AcraServer documentation](https://docs.cossacklabs.com/pages/documentation-acra/#server-side-acraserver) to describe Transparent mode in more details.

- Updated [AcraCensor documentation](https://docs.cossacklabs.com/pages/documentation-acra/#acracensor-acra-s-firewall) to describe the new configuration format and procedures for migration from the previous one.

- Updated [AcraWriter documentation](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter) for iOS and Android to reflect the improved installation ways.


## [0.84.2](https://github.com/cossacklabs/acra/releases/tag/0.84.2), February 19th 2019

_Hotfix_:

Fixed an issue in communication between AcraServer and PostgreSQL that caused AcraServer to stop processing connection due to an unexpected error in parsing packets. The issue occurred when the last data in data row column from PostgreSQL came with empty data (0 bytes).

Details: [#315](https://github.com/cossacklabs/acra/pull/315)


## [0.84.1](https://github.com/cossacklabs/acra/releases/tag/0.84.1), January 25th 2019

_Hotfix_:

Fixed an issue in the communication of AcraServer with some specific ORMs (xorm to be precise) with MySQL database. In some cases, when a database has plaintext data, AcraServer cannot decrypt it (which is OK), but it also propagated the decryption error and closed the connection (which is not OK and is fixed now).

Details: [#305](https://github.com/cossacklabs/acra/pull/305)


## [0.84.0](https://github.com/cossacklabs/acra/releases/tag/0.84), November 9th 2018

_Core_:

- **Key management**

  - Improved LRU cache: fixed concurrent access to LRU cache by adding mutex. LRU cache is used for quick access to in-memory keys (private keys are stored encrypted) in AcraServer and AcraTranslator ([#272](https://github.com/cossacklabs/acra/pull/272)).

  [AcraServer documentation](https://docs.cossacklabs.com/pages/documentation-acra/#getting-started-with-acraserver), [AcraTranslator documentation](https://docs.cossacklabs.com/pages/acratranslator/).

  - Improved AcraRotate utility: added "dry-run" mode for testing AcraRotate before it is used for real. In the "dry-run" mode AcraRotate doesn't rotate keys: it fetches AcraStructs (from files or database), decrypts, rotates in-memory keys, encrypts the data with new public keys and prints the resulting JSON with new public keys without actually saving the rotated keys and AcraStructs. As key rotation might be tricky, we want users to make sure that AcraRotate has all the required permissions and access right before actually re-encrypting the data ([#269](https://github.com/cossacklabs/acra/pull/269)).

  [AcraRotate documentation](https://docs.cossacklabs.com/pages/acrarotate/).

- **AcraWriter**

  - Added C++ AcraWriter library, added examples and tests. The library itself is a single header-only file `acrawriter.hpp` with dependency on Themis, placed in [wrappers/cpp](https://github.com/cossacklabs/acra/tree/master/wrappers/cpp). 
  Read the usage guide and examples in [examples/cpp](https://github.com/cossacklabs/acra/tree/master/examples/cpp) folder 
  ([#270](https://github.com/cossacklabs/acra/pull/270))

  [AcraWriter C++ documentation](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-c-).
  
- **Logging**

  - Improved logs of AcraConnector and AcraServer: use Debug log level for all network errors (closed connection, unavailable network, etc) and use Error log level only for cases of certainly unexpected behavior ([#275](https://github.com/cossacklabs/acra/pull/275)).

  - Improved startup logs: log process PID on start of AcraServer, AcraConnector, AcraTranslator, and AcraWebConfig ([#275](https://github.com/cossacklabs/acra/pull/275)).

  - Fixed timestamps: do not overwrite logs' timestamps ([#273](https://github.com/cossacklabs/acra/pull/273)).

- **Tracing with OpenCensus**

  - Added tracing with OpenCensus: AcraServer, AcraConnector, and AcraTranslator track every request from client application to the database and back. Each client request has a unique `traceID` that helps measure how much time it needs to perform a certain data processing functions (i.e. checking requests via AcraCensor, encrypting data, decrypting AcraStructs, etc.). Traces can be exported to Jaeger ([#279](https://github.com/cossacklabs/acra/pull/279), [#276](https://github.com/cossacklabs/acra/pull/276), [#274](https://github.com/cossacklabs/acra/pull/274)). 

  You can read more about tracing in our documentation in [Tracing in Acra](https://docs.cossacklabs.com/pages/documentation-acra/#tracing-in-acra).

  A blogpost about technical details, profits, and pitfalls during the implementation of traces is coming soon.

- **Other**

  - Improved AcraServer's connection handling: stop accepting connections after error and stop AcraServer instead of trying to accept connections after the listening socket was closed ([#275](https://github.com/cossacklabs/acra/pull/275).

  - Improved AcraCensor's handling of prepared statements for PostgreSQL binary protocol ([#280](https://github.com/cossacklabs/acra/pull/280)).

  - Improved handling of terminating packets (COM_QUIT for PostgreSQL and TerminatePacket for MySQL) to correctly handle the closing connections from clients ([#275](https://github.com/cossacklabs/acra/pull/275).

  - Refactored inner logic of AcraCensor: improved code quality and stability, added more tests that use more patterns ([#268](https://github.com/cossacklabs/acra/pull/268)).


_Infrastructure_:

- Ceased testing and supporting Go versions below 1.9. This will only affect the users who build Acra manually from sources.
  You can install the pre-built Acra components shipped for various Ubuntu, Debian, and CentOS distributives using [Installation guide](https://github.com/cossacklabs/acra/wiki/Quick-start-guide#installing-acra-from-the-cossack-labs-repository). Alternatively, you can check out our Docker images and Docker-compose files in [docker folder](https://github.com/cossacklabs/acra/tree/master/docker) 
  ([#277](https://github.com/cossacklabs/acra/pull/277)).

- Tested Acra suite with PostgreSQL v11 and MariaDB v10.3 and updated [docker compose examples](https://github.com/cossacklabs/acra/tree/master/docker) and [Acra Engineering Demo](https://github.com/cossacklabs/acra-engineering-demo/) to use it ([#278](https://github.com/cossacklabs/acra/pull/278)).

- Published [Acra load balancing demo](https://github.com/cossacklabs/acra-balancer-demo): it discovers some of the many possible variants of building high availability and balanced infrastructure based on Acra data protection suite components, PostgreSQL, and Python web application. In these examples we used HAProxy – one of the most popular high availability balancers today.

- Updated [AcraStruct Validator](https://docs.cossacklabs.com/simulator/acra/) – an online tool that can decrypt your AcraStructs. AcraStruct Validator is useful for developers who build their own AcraWriters (to validate AcraStruct binary structure).


_Features coming soon_:

- Running SQL queries over encrypted data: perform AcraServer-side lookups (search) over protected data.

- Pseudonymisation: early version of pseudonymisation library/plugin for Acra for transparent data pseudonymisation.

- Cryptographically protected audit log: protection for logs against tampering.


_Documentation_:

- [AcraWriter C++](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-c-) has a short guide for installing and using AcraWriter for C++.

- [AcraRotate](https://docs.cossacklabs.com/pages/acrarotate/): added description and notes about "dry-run" mode.

- Updated documentation for [logging](https://docs.cossacklabs.com/pages/documentation-acra/#logging-in-acra), [collecting metrics](https://docs.cossacklabs.com/pages/documentation-acra/#metrics-in-acra), and [tracing](https://docs.cossacklabs.com/pages/documentation-acra/#tracing-in-acra) in Acra.

- Many small fixes here and there to make your overall experience of using Acra's docs on a new platform distinctive and smooth ;)


## [0.83.0](https://github.com/cossacklabs/acra/releases/tag/0.83), September 28th 2018

_Core_:

- **Security**

  - Updated the default and allowed TLS configurations ([#254](https://github.com/cossacklabs/acra/pull/254)).

     Use TLS v1.2 (the latest supported version in Golang now) and limited cipher suite recommended by [Internet Assigned Numbers Authority](https://www.iana.org/assignments/tls-parameters/tls-parameters.xml) and [OWASP](https://www.owasp.org/index.php/TLS_Cipher_String_Cheat_Sheet) for most transport connections. 
  
     Use TLS v1.0 and extended cipher suit for MySQL TLS connections due to the limited support of MySQL database and drivers. 
  
  - Improved security of transport connection between Acra's services by validating the clientId length. This decreases the chance of misusing the clientId ([#253](https://github.com/cossacklabs/acra/pull/253)).

- **Key management – key rotation**

  - Added [AcraRotate](https://docs.cossacklabs.com/pages/acrarotate/) utility for rotation of Zone keys and re-encryption of AcraStructs. AcraRotate generates a new Zone keypair (`zoneid_zone.pub` and `zoneid_zone`) for a particular ZoneId and re-encrypts the corresponding AcraStructs with new keys. ZoneId stays the same ([#256](https://github.com/cossacklabs/acra/pull/256), [#239](https://github.com/cossacklabs/acra/pull/239)).

    AcraRotate doesn't affect the `ACRA_MASTER_KEY` or storage keypair used without Zones (`clientid_storage.pub` / `clientid_storage` keys).
    
    AcraRotate rotates only the Zone storage keys and affects only the AcraStructs encrypted with Zones.
    
    AcraRotate works with AcraStructs stored both in database cells (MySQL or PostgreSQL) or files.
    
    Read the full documentation on [AcraRotate on the Documentation Server](https://docs.cossacklabs.com/pages/acrarotate/).

- **AcraCensor – SQL filter and firewall**

  - Improved SQL filtering through more complex pattern matching ([#264](https://github.com/cossacklabs/acra/pull/264), [#263](https://github.com/cossacklabs/acra/pull/263), [#262](https://github.com/cossacklabs/acra/pull/262), [#238](https://github.com/cossacklabs/acra/pull/238)).
  
      - `%%VALUE%%` pattern represents literal value (string, binary, number, boolean) and is supported in the following expressions: WHERE, IN, ORDER BY, GROUP BY, BETWEEN.
      - `%%LIST_OF_VALUES%%` pattern represents several values one by one, used with IN expressions.
      - `%%SUBQUERY%%` pattern represents a subquery expression inside the main query.
      - `%%WHERE%%` pattern represents one or more expressions after a WHERE statement. This pattern works for SELECT/UPDATE/DELETE queries.
      - `%%COLUMN%%` pattern represents a column expression used after SELECT and ORDER BY expressions.
      - `%%SELECT%%` pattern represents a whole SELECT expression.


  Read the detailed description and usage examples on the [AcraCensor page on DocServer](https://docs.cossacklabs.com/pages/documentation-acra/#acracensor-acra-s-firewall).

- **AcraWriter**

  - Added Java/Android AcraWriter library, added examples and tests ([#252](https://github.com/cossacklabs/acra/pull/252)).

     Read the usage guide and examples in [examples/android_java](https://github.com/cossacklabs/acra/tree/master/examples/android_java) folder.
  
  - Added SQLAlchemy type wrappers for the Python AcraWriter ([#257](https://github.com/cossacklabs/acra/pull/257)).
  
  - Improved and refactored the Python AcraWriter example of encrypting data and reading it from the database ([#258](https://github.com/cossacklabs/acra/pull/258)).

- **Prometheus Metrics**

  - Added functionality for exporting the basic metrics of AcraServer, AcraConnector, and AcraTranslator to Prometheus: if `incoming_connection_prometheus_metrics_string` is set, the service will generate specific metrics (time of connection life, time of processing requests, AcraStruct decryption counters) and push them to Prometheus ([#260](https://github.com/cossacklabs/acra/pull/260), [#251](https://github.com/cossacklabs/acra/pull/251), [#234](https://github.com/cossacklabs/acra/pull/234)).

- **Other**

  - Improved AcraConnector's compatibility with PostgreSQL: AcraConnector now correctly handles the database's denial to use TLS connection ([#259](https://github.com/cossacklabs/acra/pull/259)).

  - Added export of CLI parameters for AcraServer, AcraConnector, and AcraTranslator to markdown ([#261](https://github.com/cossacklabs/acra/pull/261)).

  - Improved readability of CEF-formatted logs by sorting extension fields in alphabetical order ([#255](https://github.com/cossacklabs/acra/pull/255)).

  - Improved quality of our codebase — cleaned up the old unnecessary code ([#250](https://github.com/cossacklabs/acra/pull/250)).

_Infrastructure_:

  - Added AcraRotate as a ready-to-use tool inside AcraTranslator and AcraServer Docker containers ([#236](https://github.com/cossacklabs/acra/pull/236)).


_Documentation_:

- Made the [Documentation Server](https://docs.cossacklabs.com/) the primary and the only regularly updated source of [documentation for Acra](https://docs.cossacklabs.com/products/acra/). The most recent version of the [documentation](https://docs.cossacklabs.com/products/acra/#documentation), [tutorials](https://docs.cossacklabs.com/products/acra/#tutorials), and [demos](https://docs.cossacklabs.com/products/acra/#undefined) for Acra can be found there. The [GitHub Wiki documentation](https://github.com/cossacklabs/acra/wiki) for Acra is still available, but is no longer updated starting with the version 0.82.0 (with the exception of Changelog and README files with every new version release).

- [AcraCensor](https://docs.cossacklabs.com/pages/documentation-acra/#acracensor-acra-s-firewall): updated the details on how the "patterns" filter works.

- [AcraRotate](https://docs.cossacklabs.com/pages/acrarotate/): added a tutorial for using AcraRotate to rotate Zone keys and re-encrypt the data.

- Tons of small fixes here and there to make your overall experience of using Acra's docs on a new platform distinctive and smooth ;).


## [0.82.0](https://github.com/cossacklabs/acra/releases/tag/0.82), August 14th 2018

_Core_:

- **AcraTranslator**

  AcraTranslator is a lightweight server that receives [AcraStructs](https://github.com/cossacklabs/acra/wiki/AcraStruct) and returns the decrypted data. AcraTranslator doesn’t care about the source of the data, it accepts AcraStructs via HTTP or gRPC API. An application can store AcraStructs anywhere it is convenient: as cells in the database, as files in the file storage (local or cloud storage, like [AWS S3](https://aws.amazon.com/ru/s3/)). An application sends AcraStructs as binary data and receives plaintext (or decryption error) from AcraTranslator.

  However, sending plaintext data over a non-secure channel is a bad idea, so AcraTranslator requires the use of [Themis Secure Session](https://github.com/cossacklabs/themis/wiki/Secure-Session-cryptosystem) encryption channel (which is basically an encrypted TCP/unix sockets). To establish a Secure Session connection, an application doesn’t need to contain the crypto-code itself, only to direct the traffic through AcraConnector instead.

  AcraTranslator supports AcraStructs via HTTP and gRPC API, uses in-memory LRU cache to store encryption keys, and detects poison records. AcraTranslator is shipped as a pre-built binary and as a Docker container.

  Read [the detailed guide](https://github.com/cossacklabs/acra/wiki/AcraTranslator) on how to install, configure, and run AcraTranslator.
  
([#213](https://github.com/cossacklabs/acra/pull/213), [#212](https://github.com/cossacklabs/acra/pull/212), [#207](https://github.com/cossacklabs/acra/pull/207), [#205](https://github.com/cossacklabs/acra/pull/205), [#204](https://github.com/cossacklabs/acra/pull/204), [#203](https://github.com/cossacklabs/acra/pull/203), [#200](https://github.com/cossacklabs/acra/pull/200), [#199](https://github.com/cossacklabs/acra/pull/199), [#198](https://github.com/cossacklabs/acra/pull/198), [#197](https://github.com/cossacklabs/acra/pull/197))


  - Updated AcraConnector to support connections with AcraTranslator ([#206](https://github.com/cossacklabs/acra/pull/206)).


- **Logging**

  - Improved startup logs for AcraServer, AcraTranslator, and AcraConnector: now it's easier to understand that the service is up and running ([#242](https://github.com/cossacklabs/acra/pull/242)).

  - Added clientId to AcraServer logs: now it's easier to understand which client was sending the request that led to a failed or successful AcraStruct decryption ([#214](https://github.com/cossacklabs/acra/pull/214)).

  - Improved logging by masking query parameters: neither AcraServer nor AcraCensor won't leak sensitive query while logging the content ([#216](https://github.com/cossacklabs/acra/pull/216), [#211](https://github.com/cossacklabs/acra/pull/211)).


- **Poison records**

  - Poison record detection for AcraServer and AcraTranslator can now be turned on and off. Poison records detection is ON by default: AcraServer/AcraTranslator will try to detect poison record and log to stderr if a poison record is detected ([#240](https://github.com/cossacklabs/acra/pull/240), [#230](https://github.com/cossacklabs/acra/pull/230), [#215](https://github.com/cossacklabs/acra/pull/215)).

  - Increased performance of AcraServer/AcraTranslator if poison records are enabled ([#232](https://github.com/cossacklabs/acra/pull/232)).


- **Key management**

  - Improved processing of decryption keys for AcraServer, AcraTranslator, and AcraConnector: now it is possible to store private keys encrypted in files and in memory, decrypt them before using, and purge after usage ([#202](https://github.com/cossacklabs/acra/pull/202)).

  - Added configurable LRU cache for the in-memory keys: this will increase the performance if you operate with hundreds of storage keys on AcraServer and AcraTranslator ([#219](https://github.com/cossacklabs/acra/pull/219)).


- **AcraCensor – SQL filter and firewall**

  - Improved SQL filtering by adding pattern matching: now you can blacklist or whitelist queries that match particular patterns, like `SELECT %%COLUMN%% FROM company %%WHERE%%`. 

  Currently supported patterns: `%%VALUE%%`, `%%COLUMN%%`, `%%WHERE%%` and `%%SELECT%%`. 

  Read the detailed description and usage examples on the [AcraCensor page](https://github.com/cossacklabs/acra/wiki/AcraCensor).
  
  ([#248](https://github.com/cossacklabs/acra/pull/248), [#247](https://github.com/cossacklabs/acra/pull/247), [#246](https://github.com/cossacklabs/acra/pull/246), [#245](https://github.com/cossacklabs/acra/pull/245), [#243](https://github.com/cossacklabs/acra/pull/243), [#238](https://github.com/cossacklabs/acra/pull/238), [#231](https://github.com/cossacklabs/acra/pull/231), [#226](https://github.com/cossacklabs/acra/pull/226), [#217](https://github.com/cossacklabs/acra/pull/217))

  - Improved AcraCensor performance for queries matching ([#208](https://github.com/cossacklabs/acra/pull/208)).

- **AcraWriter**

  - Added iOS/Objective-C AcraWriter library as CocoaPod, added examples and tests.

  Read the usage guide and examples in [examples/objc](https://github.com/cossacklabs/acra/tree/master/examples/objc) folder.
  
  ([#241](https://github.com/cossacklabs/acra/pull/241), [#235](https://github.com/cossacklabs/acra/pull/235), [#233](https://github.com/cossacklabs/acra/pull/233)).

  - Improved security of AcraWriter libs for Go, Ruby, Nodejs, and iOS through zeroing secret keys where it was missing ([#244](https://github.com/cossacklabs/acra/pull/244)).


- **AcraRollback**

  - Improved handling of `insert` query parameter to simplify using AcraRollback from bash ([#210](https://github.com/cossacklabs/acra/pull/210)).

- **Other**

  - Improved AcraStruct decryption by multiple validations of AcraStruct format before decrypting. This fix improves AcraServer/AcraTranslator error messages in case of a failed decryption ([#201](https://github.com/cossacklabs/acra/pull/201)).

  - Improved stability of integration test suite, trying to avoid 'timed out' errors from CircleCI ([#200](https://github.com/cossacklabs/acra/pull/220)).

  - Improved code quality, fixing gofmt and golint issues ([#229](https://github.com/cossacklabs/acra/pull/229), [#228](https://github.com/cossacklabs/acra/pull/228), [#227](https://github.com/cossacklabs/acra/pull/227), [#224](https://github.com/cossacklabs/acra/pull/224), [#223](https://github.com/cossacklabs/acra/pull/223), [#221](https://github.com/cossacklabs/acra/pull/221)).

- **WIP**

  - Adding a way to export decryption metrics (decryption time, number of connections) from AcraServer to Prometeus ([#234](https://github.com/cossacklabs/acra/pull/234)).

  - Prototyping AcraRotate tool for rotating the Zone keys easily ([#239](https://github.com/cossacklabs/acra/pull/239)).


_Infrastructure_:

  - Drop testing and supporting go version below 1.8. This will only affect the users who build Acra manually from sources.
  You can install pre-built Acra components shipped for various Ubuntu, Debian, and CentOS distributives using [Installation guide](https://github.com/cossacklabs/acra/wiki/Quick-start-guide#installing-acra-from-the-cossack-labs-repository). Alternatively, you can check out our Docker images and Docker-compose files in [docker folder](https://github.com/cossacklabs/acra/tree/master/docker) 
  ([#209](https://github.com/cossacklabs/acra/pull/209)).

  - Added AcraTranslator as pre-built binary and docker container ([#222](https://github.com/cossacklabs/acra/pull/222)).

  - Added AcraTranslator and AcraConnector docker-compose files: now it's easy to set up a demo stand just by running one command ([#225](https://github.com/cossacklabs/acra/pull/225)).

  - Added AcraRollback and AcraPoisonRecordMaker as ready-to-use tools inside AcraTranslator and AcraServer Docker containers ([#236](https://github.com/cossacklabs/acra/pull/236)).


_Documentation_:

- [Key management](https://github.com/cossacklabs/acra/wiki/Key-Management): clarified key names and default locations, illustrated public key exchange in details.

- [AcraServer](https://github.com/cossacklabs/acra/wiki/How-AcraServer-works): improved examples of how to run AcraServer.

- [AcraTranslator](https://github.com/cossacklabs/acra/wiki/Home): added description of the service, installation and launching guide, added ready-to-use examples for HTTP and gRPC API.

- [AcraConnector](https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter): added examples of how to run AcraConnector with AcraTranslator.

- [AcraCensor](https://github.com/cossacklabs/acra/wiki/AcraCensor): added examples of the configuration file, described in details how the "patterns" filter works.

- [AcraRollback](https://github.com/cossacklabs/acra/wiki/AcraRollback): added examples of running AcraRollback in local mode, which allows storing the decrypted data locally, without pushing it back to the database.

- This is the last version of Acra for which the main documentation will be actively updated in the GitHub Wiki. From now on, the most recent version of the documentation, tutorials, and demos for Acra will be available in the [official Cossack Labs Documentation Server](https://docs.cossacklabs.com/products/acra/). 




## [0.81.0](https://github.com/cossacklabs/acra/releases/tag/0.81), July 6th 2018

_Core_:

- **Prepared Statements**

   - Added support of prepared statements for PostgreSQL/MySQL. Both binary and text response formats are supported ([#192](https://github.com/cossacklabs/acra/pull/192)).

- **SQL requests filtering in AcraCensor**

   AcraCensor got smarter in preventing SQL Injections.

   - Improved flexibility for parsing queries. If AcraCensor can't parse an SQL query, it is considered as potentially too dangerous to send it to the database, so AcraCensor blocks such "unparseable" queries by default. 
   However, setting the configuration flag `ignore_parse_error` to `true` will make AcraCensor ignore the "unparseable" quality of queries and send them to the database anyway. Check out the configuration example in [configs/acra-censor.example.yaml](https://github.com/cossacklabs/acra/blob/master/configs/acra-censor.example.yaml) ([#194](https://github.com/cossacklabs/acra/pull/194)).

   - Added support of complex JOIN queries ([#191](https://github.com/cossacklabs/acra/pull/191)).

   - Improved reading/writing QueryCapture log file. Now AcraCensor uses bufferisation before writing queries into a log file. 
   Changed format of QueryCapture log to JSON Line (each query sits in a separate line in a log file instead of having an array of JSON objects) ([#193](https://github.com/cossacklabs/acra/pull/193)).

   - Introduced a few fixes here and there, made integration tests for AcraCensor more stable ([#184](https://github.com/cossacklabs/acra/pull/184)).

- **Improving MySQL support**

   We introduced MySQL support just a few Acra releases ago and we continue polishing it. Now we've updated the example projects so you can jump right into the code!

   Take a look at how to use Acra for both PostreSQL and MySQL databases in these examples:

   - Go: see the [examples/golang](https://github.com/cossacklabs/acra/tree/master/examples/golang/src) folder ([#190](https://github.com/cossacklabs/acra/pull/190)).

   - Ruby: see the [examples/ruby](https://github.com/cossacklabs/acra/tree/master/examples/ruby) folder ([#189](https://github.com/cossacklabs/acra/pull/189)).

   - Python: see the [examples/python](https://github.com/cossacklabs/acra/tree/master/examples/python) folder ([#188](https://github.com/cossacklabs/acra/pull/188)).

- **Other**

   - Updated handling of message formats for PostgreSQL and MySQL protocols ([#186](https://github.com/cossacklabs/acra/pull/186)).

   - Improved logging in CEF and JSON formats for high load systems ([#195](https://github.com/cossacklabs/acra/pull/195)).

   - Added comprehensive `Readme` to every project in [/examples](https://github.com/cossacklabs/acra/tree/master/examples) folder ([#196](https://github.com/cossacklabs/acra/pull/196)).

   - Added pre-generated configuration file for AcraAuthmanager. Now it's easier to configure AcraServer using [AcraWebconfig](https://github.com/cossacklabs/acra/wiki/AcraWebConfig) ([#187](https://github.com/cossacklabs/acra/pull/187)).


_Documentation_:

- Updated Acra [Architecture and Data flow](https://github.com/cossacklabs/acra/wiki/Architecture-and-data-flow) graphic schemes to better illustrate Acra's components, connections between them, and typical use-cases.
- Updated AcraCensor's description to explain how [unparseable queries](https://github.com/cossacklabs/acra/wiki/AcraCensor#unparseable-queries) are handled.    
- Described typical [Public Key Infrastructure](https://github.com/cossacklabs/acra/wiki/PKI-overview-for-Acra) with some advice on where to put Acra in the general scheme of things.
- Described Acra's [Security Model](https://github.com/cossacklabs/acra/wiki/Acra's-Security-Model), possible threats, and possible consequences of compromisation.
- Added a page describing the ways [Acra can help you better comply with GDPR](https://github.com/cossacklabs/acra/wiki/Acra-and-GDPR-compliance).


## [0.80.0](https://github.com/cossacklabs/acra/releases/tag/0.80), May 31st 2018

_Core_:

- **Renaming**

   - Global renaming of Acra components and their configuration parameters. 
   We believe that the updated naming will decrease confusion about the components' functions and will make Acra's setup and usage process easier.

   _Main services:_
   
   | Old name | New name | Function |
   | --- | --- | --- |
   | AcraServer | AcraServer | decrypts data from the database |
   | AcraWriter | AcraWriter | encrypts data on the client side |
   | AcraProxy | AcraConnector | encrypts traffic between the client and the server using Themis Secure Session |
   | AcraCensor | AcraCensor | firewall, part of AcraServer, blocks suspicious SQL requests to the database |
   | AcraConfigUI | AcraWebConfig | lightweight HTTP web server for managing AcraServer's certain configuration options |

   _Utilities:_

   | Old name | New name | Function |
   | --- | --- | --- |
   | acra_rollback | AcraRollback | decrypts the whole database |
   | acra_genkeys | AcraKeymaker | generates encryption keys for storage and transport of the Acra components |
   | acra_genauth | AcraAuthmanager | generates user accounts for AcraWebConfig |
   | acra_genpoisonrecord | AcraPoisonRecordMaker | generates poison records for databases |
   | acra_addzone | AcraAddzone | generates Zones' header for AcraWriter |

   Check the configurations of components inside [/configs folder](https://github.com/cossacklabs/acra/tree/master/configs) and read [Migration Guide](https://github.com/cossacklabs/acra/wiki/Migration-guide) for more details ([#175](https://github.com/cossacklabs/acra/pull/175), [#174](https://github.com/cossacklabs/acra/pull/174), [#173](https://github.com/cossacklabs/acra/pull/173), [#170](https://github.com/cossacklabs/acra/pull/170), [#169](https://github.com/cossacklabs/acra/pull/169), [#168](https://github.com/cossacklabs/acra/pull/168)).

- **SSL/TLS**

   - Improved SSL/TLS connections between AcraServer<->AcraConnector and AcraServer<->database. Added TLS authentication mode (`tls_auth`) argument to the AcraServer/AcraConnector configuration files: 
      - for AcraConnector it indicates how to authenticate AcraServer during a TLS connection; 
      - for AcraServer it indicates how to authenticate database during a TLS connection.
   - Updated TLS configuration to provide other less strict authentication methods (do not authenticate client from server, ask for any certificate, ask and check) ([#171](https://github.com/cossacklabs/acra/pull/171)).

- **SQL requests filtering**

   - Added support of filtering SQL requests for PostgreSQL databases. Now you can setup AcraCensor rules for both MySQL and PostgreSQL databases ([#177](https://github.com/cossacklabs/acra/pull/177)).
   
   - Improved [QueryCapture](https://github.com/cossacklabs/acra/wiki/acracensor): AcraCensor writes allowed/blocked queries into a separate log file without blocking the main process ([#176](https://github.com/cossacklabs/acra/pull/176), [#172](https://github.com/cossacklabs/acra/pull/172)).

   See a detailed description of AcraCensor on the corresponding [AcraCensor documentation page](https://github.com/cossacklabs/acra/wiki/acracensor).

- **AcraWriter in Ruby**

   - Updated AcraWriter Ruby wrapper for [ActiveRecord tutorial](https://github.com/cossacklabs/acra/wiki/Using-Acra-to-Protect-Your-Rails-App) and pushed a new gem ([#166](https://github.com/cossacklabs/acra/pull/166)).


- **Key Handling**

   - Added `make keys` target in the Makefile: one command now generates keys and places them into correct folders for all Acra components ([#182](https://github.com/cossacklabs/acra/pull/182), [#181](https://github.com/cossacklabs/acra/pull/181)).
   - Improved handling of master key length longer than 32 bytes ([#183](https://github.com/cossacklabs/acra/pull/183)).
   
- **Other**

   - Updated notification when AcraConnector is launched in an environment without `netstat` ([#167](https://github.com/cossacklabs/acra/pull/167)).
   - Updated error handling for AcraServer working with Zones and fix some corner-cases in using PostgreSQL protocol ([#186](https://github.com/cossacklabs/acra/pull/186), [#179](https://github.com/cossacklabs/acra/pull/179)).


_Infrastructure_:

- **Even better Docker support**

   - Added more ready-to-use Docker Containers: `acra-keymaker`, `acra-authmanager`. As a result, each Acra component is wrapped into a Docker container, allowing you to try Acra into your infrastructures easily.

   - Added easy-to-use docker-compose files for setting up the whole Acra-based environment connected to MySQL database. Possible configurations include setup with/without SSL, with/without AcraConnector, with/without Zones ([#180](https://github.com/cossacklabs/acra/pull/180)).
   Check out the instructions and examples in the [/docker](https://github.com/cossacklabs/acra/tree/master/docker) folder: we have examples for both MySQL and PostgreSQL databases.

   - Updated descriptions for official Cossack Labs packages on [Docker Hub](https://hub.docker.com/u/cossacklabs/).

   - Updated [Getting started with Docker](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker) guide to make starting out with Acra even easier.

- **OS**

   - Added support of Ubuntu Xenial, Ubuntu Bionic (added precompiled binaries and tests to make sure that Acra is compiling/building/working well on 16.04/18.04).


_Documentation_:

- Updated tutorials about protecting a [Ruby on Rails app](https://github.com/cossacklabs/acra/wiki/Using-Acra-to-Protect-Your-Rails-App) and a [Django app](https://github.com/cossacklabs/acra/wiki/Using-Acra-to-Protect-Your-Django-App).
- Every single document, code line, and image are updated using the new naming.
- Significant parts of the [README](https://github.com/cossacklabs/acra/blob/master/README.md) have been rewritten.



## [0.77.0](https://github.com/cossacklabs/acra/releases/tag/0.77), April 13th 2018


_Core_:

- **MySQL databases**

	- Added support for MySQL: now  you can connect Acra to MySQL databases. Works with any SSL mode: `require`, `allow`, `disable`.
	- Tested and supported on: MySQL ([#155](https://github.com/cossacklabs/acra/pull/155), [#140](https://github.com/cossacklabs/acra/pull/140)).

	> Note: Prepared statements are not supported yet, but this feature is coming soon!
	
	Read about the new configurations on the [AcraServer](https://github.com/cossacklabs/acra/wiki/How-AcraServer-works) documentation page.

- **Keeping keys in secret**

	- Added encryption for the keys' folder: private keys are now symmetrically encrypted by `master_key` ([#143](https://github.com/cossacklabs/acra/pull/143)) for storage.
	- Added ability to generate public/private keys in the separate folders ([#148](https://github.com/cossacklabs/acra/pull/148), [#142](https://github.com/cossacklabs/acra/pull/142)).

	Read more about the current changes in [key management here](https://github.com/cossacklabs/acra/wiki/Key-Management).

- **Filtering requests for MySQL**

	- Added firewall component named [AcraCensor](https://github.com/cossacklabs/acra/wiki/acracensor) to handle MySQL queries. <br/>
	You can provide a list of restricted or allowed tables, columns, and exact queries to handle. AcraCensor will pass the allowed queries and return error on forbidden ones. Rules are configured and stored in `yaml` file. Each request is logged in real time. Moreover, all the queries and their states are logged into a separate log file. ([#151](https://github.com/cossacklabs/acra/pull/151), [#138](https://github.com/cossacklabs/acra/pull/138), [#136](https://github.com/cossacklabs/acra/pull/136), [#132](https://github.com/cossacklabs/acra/pull/132), [#125](https://github.com/cossacklabs/acra/pull/125), [#108](https://github.com/cossacklabs/acra/pull/108)).<br/>

	See a detailed description of AcraCensor on the corresponding [AcraCensor documentation page](https://github.com/cossacklabs/acra/wiki/acracensor).

- **Web Config UI**

	- Added lightweight HTTP [web server](https://github.com/cossacklabs/acra/wiki/AcraConfigUI) for managing AcraServer's certain configuration options.<br/>
	You can update the proxy address and port, database address and port, handling of Zone mode and poison records. On saving new configuration, `acraserver` will gracefully restart and use these settings automatically. The access to thiw web page is restricted using basic auth. ([#153](https://github.com/cossacklabs/acra/pull/153), [#141](https://github.com/cossacklabs/acra/pull/141), [#123](https://github.com/cossacklabs/acra/pull/123), [#111](https://github.com/cossacklabs/acra/pull/111)).<br/>

	See the interface screenshot and detailed instructions at [Acra Config UI](https://github.com/cossacklabs/acra/wiki/AcraConfigUI) page.


- **Logging**
	- Added support of new logging formats: plaintext, [CEF](https://kc.mcafee.com/resources/sites/MCAFEE/content/live/CORP_KNOWLEDGEBASE/78000/KB78712/en_US/CEF_White_Paper_20100722.pdf), and json.<br/>
	Logging mode and verbosity level is configured for AcraServer, AcraProxy, and AcraConfigUI in the corresponding `yaml` files. Log messages were slightly improved, custom error codes were added (which we believe will help to understand and debug any issues) ([#135](https://github.com/cossacklabs/acra/pull/135), [#126](https://github.com/cossacklabs/acra/pull/126), [#110](https://github.com/cossacklabs/acra/pull/110)).
	
	Read more about the log analysis at [Logging](https://github.com/cossacklabs/acra/wiki/Logging) page.


- **Tests**

	- Added many new integartion tests, fixed stability and handling of more complicated use-cases ([#150](https://github.com/cossacklabs/acra/pull/150), [#147](https://github.com/cossacklabs/acra/pull/147), [#137](https://github.com/cossacklabs/acra/pull/137), [#117](https://github.com/cossacklabs/acra/pull/117), [#116](https://github.com/cossacklabs/acra/pull/116), [#115](https://github.com/cossacklabs/acra/pull/115)).


_Infrastructure_:

- **Docker support**
	
	- Added Docker Container for every main component: `AcraServer`, `AcraProxy`, `AcraConfigUI`, and key generators (`AcraGenKeys` and `AcraGenAuth`). You can find the containers in [/docker](https://github.com/cossacklabs/acra/tree/master/docker) folder or on the [Docker Hub](https://hub.docker.com/r/cossacklabs/) ([#139](https://github.com/cossacklabs/acra/pull/139)).
	- Updated [Getting started with Docker](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker) guide to make starting out with Acra even easier.

	- Added easy-to-use docker-compose files to launch Acra in different environments, including key distribution. Possible configurations are:
		- `acraserver` + `acra_configui `;
		- connecting to PostreSQL or MySQL databases;
		- using Secure Session or SSL as transport encryption;
		- with or without `acraproxy`;
		- with or without zones.<br/>

		This is huge! We encourage you to try it! Check out the instructions and examples in the [/docker](https://github.com/cossacklabs/acra/tree/master/docker) folder.  ([#154](https://github.com/cossacklabs/acra/pull/154), [#146](https://github.com/cossacklabs/acra/pull/146), [#134](https://github.com/cossacklabs/acra/pull/134), [#133](https://github.com/cossacklabs/acra/pull/133), [#102](https://github.com/cossacklabs/acra/pull/102)).

- **Go versions**
	
	- Updated the list of supported versions of Go. Every Acra component can now be built using Go >1.7, except `acra_rollback` that requires Go >1.8. No worries, you can still download Acra as a binary package anyway :)

- **OS**

	- Dropped support of Debian Wheezy (no autotests, no precompiled binaries now).


_Documentation_:

- Updated [QuickStart](https://github.com/cossacklabs/acra/wiki/Quick-start-guide) documentation about launching and building Acra components.
- Described how to setup [AcraCensor](https://github.com/cossacklabs/acra/wiki/acracensor) and [AcraConfigUI](https://github.com/cossacklabs/acra/wiki/AcraConfigUI).
- Added more details and described new options (like using TLS and connecting to MySQL databases) for [AcraServer](https://github.com/cossacklabs/acra/wiki/How-AcraServer-works) and [AcraProxy](https://github.com/cossacklabs/acra/wiki/AcraProxy-and-AcraWriter).
- Described new [logging](https://github.com/cossacklabs/acra/wiki/Logging) formats.
- Updated description of [Key management](https://github.com/cossacklabs/acra/wiki/Key-Management) approach we encourage you to use.
- Described Docker components and ready-to-use Docker Compose configurations based on the [Docker Readme](https://github.com/cossacklabs/acra/tree/master/docker).
- Updated [Getting started with Docker](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker) guide.
- Distributed the information about master key across the docs.
- Many small improvements.




## [0.76](https://github.com/cossacklabs/acra/releases/tag/0.76), March 9th 2018


_Core_:

- **SSL / TLS support**

Now you can use PostgeSQL with SSL/TLS settings enabled. Acra supports two modes of connection between AcraServer and the database: using SSL/TLS or using Secure Session ([#113](https://github.com/cossacklabs/acra/pull/113), [#119](https://github.com/cossacklabs/acra/pull/119)).


- **Unix sockets**

Acra now supports usage of both TCP and Unix Sockets as a connection layer between AcraWriter <-> AcraProxy <-> AcraServer.

- **Tests**

	- Updated integration test suit to support multiple connection modes between the Acra components and the database ([#115](https://github.com/cossacklabs/acra/pull/115), [#117](https://github.com/cossacklabs/acra/pull/117), [#118](https://github.com/cossacklabs/acra/pull/118), [#120](https://github.com/cossacklabs/acra/pull/120)).
	- Added Docker image to make testing easier ([#104](https://github.com/cossacklabs/acra/pull/104)).


_Infrastructure_:

- Added support of Go 1.10, removed support of older Go versions (<1.6).
- Added support of Ubuntu 17.10, Ubuntu 16.04, Ubuntu 14.04, Debian Stretch.
- Updated dependency libraries (libthemis and libcrypto) to use the latest ones.


_Documentation_:

- Updated the documentation and tutorials to reflect the latest changes.


## [0.75](https://github.com/cossacklabs/acra/releases/tag/0.75), March 7th 2017

This is the initial public release of Acra, a database protection suite.

This version of Acra:

- works on Ubuntu, CentOS, Debian linuxes
- supports PostgreSQL 9.4+
- has AcraWriter packages for Python, PHP, Go and NodeJS
