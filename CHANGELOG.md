# Acra ChangeLog

## [0.84.0](https://github.com/cossacklabs/acra/releases/tag/0.84), November 9th 2018

_Core_:

- **Key management**

  - Improved LRU cache: fixed concurrent access to LRU cache by adding mutex. LRU cache is used for quick access to in-memory keys (private keys are stored encrypted) in AcraServer and AcraTranslator ([#272](https://github.com/cossacklabs/acra/pull/272)).

  [AcraServer documentation](https://docs.cossacklabs.com/pages/documentation-acra/#getting-started-with-acraserver), [AcraTranslator documentation](https://docs.cossacklabs.com/pages/acratranslator/).

  - Improved AcraRotate utility: added "dry-run" mode for testing AcraRotate before real usage. In "dry-run" mode AcraRotate doesn't rotate keys: it fetches AcraStructs (from files or database), decrypts, rotates in memory keys, encrypts data with new public keys and prints resulting JSON with new public keys without actually saving rotated keys and AcraStructs. Key rotation might be tricky we want users to make sure that AcraRotate has required permissions and access before actually re-encrypting the data ([#269](https://github.com/cossacklabs/acra/pull/269)).

  [AcraRotate documentation](https://docs.cossacklabs.com/pages/acrarotate/).

- **AcraWriter**

  - Added C++ AcraWriter library, added examples and tests. Library itself is a single header-only file `acrawriter.hpp` with dependency on Themis, placed in [wrappers/cpp](https://github.com/cossacklabs/acra/tree/master/wrappers/cpp). 
  Read the usage guide and examples in [examples/cpp](https://github.com/cossacklabs/acra/tree/master/examples/cpp) folder.

  ([#270](https://github.com/cossacklabs/acra/pull/270))

- **Logging**

  - Improved logs of AcraConnector and AcraServer: use Debug log level for all network errors (closed connection, unavailable network, etc), use Error log level only in cases of certainly unexpected behavior ([#275]https://github.com/cossacklabs/acra/pull/275).

  - Improved start up logs: log process PID on start of AcraServer, AcraConnector, AcraTranslator and AcraWebConfig ([#275]https://github.com/cossacklabs/acra/pull/275).

  - Fixed timestamps: do not overwrite logs timestamps ([#273](https://github.com/cossacklabs/acra/pull/273)).

- **Tracing with OpenCensus**

  - Added tracing with OpenCensus: AcraServer, AcraConnector and AcraTranslator now allow to track every request from client application to the database and back. Each client request has unique `traceID` and shows how much time it needs to perform a certain processing functions (like checking requests via AcraCensor, encrypting data, decrypting AcraStructs, ect). Traces can be exported to Jaeger ([#276](https://github.com/cossacklabs/acra/pull/276), [#274](https://github.com/cossacklabs/acra/pull/274)). 

  Read more about tracing in our documentation (ссылка на доки).

  Technical blogpost about profits and pitfalls during implementing traces is coming soon.

- **Other**

  - Improved AcraServer's connection handling: stop accepting connections after error and stop AcraServer instead of trying to accept connections after listening socket was closed ([#275]https://github.com/cossacklabs/acra/pull/275).

  - Improved handling of terminating packets (COM_QUIT for PostgreSQL and TerminatePacket for MySQL) to correctly handle closing connections from clients ([#275]https://github.com/cossacklabs/acra/pull/275).

  - Refactored inner logic of AcraCensor: improved code quality and stability, added more tests that use more patterns ([#268](https://github.com/cossacklabs/acra/pull/268)).


_Infrastructure_:

- Tested Acra suite with PostgreSQL 11 and updated [Acra Engineering Demo](https://github.com/cossacklabs/acra-engineering-demo) to use it.

- Published [Acra load balancing demo](https://github.com/cossacklabs/acra-balancer-demo): it discovers some of many possible variants of building high availability and balanced infrastructure, based on Acra data protection suite components, PostgreSQL and python web application. In these examples we used HAProxy – one of the most popular high availability balancers today.

- Updated [AcraStruct Validator](https://docs.cossacklabs.com/simulator/acra/) – an online tool that can decrypt your AcraStructs. AcraStruct Validator is useful for developers who build their own AcraWriters (to validate AcraStruct binary structure).


_Features coming soon_:

- **Search in encrypted data**

- **Pseudonymization**


_Documentation_:

- AcraWriter C++

- AcraRotate with dry run mode

- Tracing

- Tons of small fixes here and there to make your overall experience of using Acra's docs on a new platform distinctive and smooth ;)


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
