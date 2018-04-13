# Acra ChangeLog

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
