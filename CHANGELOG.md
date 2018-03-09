# Acra ChangeLog


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
