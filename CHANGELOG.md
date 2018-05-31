# Acra ChangeLog

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
   | acra_genpoisonrecord | AcraPoisonRecordMaker | generates poision records for databases |
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
