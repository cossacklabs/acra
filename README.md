<h3 align="center">
  <a href="https://www.cossacklabs.com/acra/"><img src="https://github.com/cossacklabs/acra/wiki/Images/acralogo.png" alt="Acra: database security suite" width="420"></a>
  <br>
  Database protection suite with field level encryption and intrusion detection.
  <br>
</h3>

-----

<p align="center">
  <a href="https://github.com/cossacklabs/acra/releases"><img src="https://img.shields.io/github/release/cossacklabs/acra.svg" alt="GitHub release"></a>
  <a href="https://circleci.com/gh/cossacklabs/acra"><img src="https://circleci.com/gh/cossacklabs/acra/tree/master.svg?style=shield" alt="Circle CI"></a>
  <a href='https://coveralls.io/github/cossacklabs/themis'><img src='https://coveralls.io/repos/github/cossacklabs/themis/badge.svg?branch=master' alt='Coverage Status' /></a>
  <a href='https://goreportcard.com/report/github.com/cossacklabs/acra'><img class="badge" tag="github.com/cossacklabs/acra" src="https://goreportcard.com/badge/github.com/cossacklabs/acra"></a>
  <a href='https://godoc.org/github.com/cossacklabs/acra'><img src='https://godoc.org/github.com/cossacklabs/acra?status.svg'  alt='godoc'/></a>
  <br/><a href="https://github.com/cossacklabs/acra/releases/latest"><img src="https://img.shields.io/badge/Server%20Platforms-Ubuntu%20%7C%20Debian%20%7C%20CentOS-green.svg" alt="Server platforms"></a>
  <a href="https://github.com/cossacklabs/acra/releases/latest"><img src="https://img.shields.io/badge/Client%20Platforms-Go%20%7C%20Ruby%20%7C%20Python%20%7C%20PHP%20%7C%20NodeJS%20%7C%20C++%20%7C%20iOS%20%7C%20Android-green.svg" alt="Client platforms"></a>
  <a href="https://marketplace.digitalocean.com/apps/acra?action=deploy"><img src="https://img.shields.io/badge/Install%20on-DigitalOcean-blue" alt="Install on DigitalOcean"></a>
</p>
<br>

| [Acra Engineering Examples](https://github.com/cossacklabs/acra-engineering-demo) | [Documentation and tutorials](https://docs.cossacklabs.com/acra/) | [Installation](https://github.com/cossacklabs/acra#installation-and-launch) |
| ---- | ---- | ---- |


## What is Acra
Acra — database security suite for sensitive and personal data protection.

Acra provides [application-level encryption](https://www.infoq.com/articles/ale-software-architects/) for data fields, multi-layered access control, database leakage prevention, and intrusion detection capabilities in one suite. Acra was specifically designed for distributed apps (web, server-side and mobile) that store data in one or many databases / datastores.

<table><thead><tr><th>Perfect Acra-compatible applications</th>
<th>Typical industries</th></tr></thead>
<tbody><tr><td>Web and mobile apps that store data in a centralised database or object storage</td>
<td rowspan=3><ul>
<li>Healthcare, patient apps</li>
<li>Finance, fintech, neobanking</li>
<li>SaaS</li>
<li>Critical infrastructures</li>
<li>Apps with > 1000 users</li></ul></td>
</tr><tr><td>IoT apps that collect telemetry and process data in the cloud</td>
</tr><tr><td>High-load data processing apps</td>
</tr></tbody></table>

Acra gives you tools for encrypting each sensitive data record (data field, database cell, json) before storing them in the database / file storage. And then decrypting them in a secure compartmented area (on Acra side). Acra allows to encrypt data as early as possible and operate on encrypted data.

Acra's [cryptographic design](https://docs.cossacklabs.com/acra/acra-in-depth/security-design/) ensures that no secret (password, key, etc.) leaked from the application or database will be sufficient for decryption of the protected data. Acra minimises the leakage scope, detects unauthorised behavior, and prevents the leakage, informing operators of the incident underway.

This is [Acra Community Edition](https://www.cossacklabs.com/acra/#pricing), it's free for commercial and non-commercial use, forever.

<p align="center"><img src="https://github.com/cossacklabs/acra/wiki/Images/readme/main-animation-v2.gif" alt="User Acra suite for protecting data" width="760"></p>

### Major security features

<table><tbody><tr><tr><td><li><a href="https://docs.cossacklabs.com/acra/security-controls/encryption/">Application-level encryption</a></li></td><td> encryption on client-side and/or Acra-side – each data field is encrypted using unique encryption keys.</td>
</tr><tr><td><li>Selective encryption </li></td><td>you select which columns to encrypt to balance good security and performance.</td>
</tr><tr><td><li><a href="https://docs.cossacklabs.com/acra/acra-in-depth/cryptography-and-key-management/" target=_blank>Fast and reliable crypto</a></li></td><td>two crypto-envelopes: <a href="https://docs.cossacklabs.com/acra/acra-in-depth/data-structures/">AcraBlocks and AcraStructs</a>.<br>AcraBlocks are fast symmetric containers, use them by default.<br>AcraStructs are asymmetric containers, use them for client-side encryption.</td>
</tr><tr><td><li><a href="https://docs.cossacklabs.com/acra/security-controls/searchable-encryption/">Searchable encryption</a></li></td><td>search by query without decryption. Designed for <i>exact</i> queries, based on AES-GCM and blind index.</td>
</tr><tr><td><li><a href="https://docs.cossacklabs.com/acra/security-controls/masking/">Masking / anonymization</a></li></td><td>use full or partial masking to remove or mask sensitive data.</td>
</tr><tr><td><li><a href="https://docs.cossacklabs.com/acra/security-controls/tokenization/">Tokenization</a></li></td><td>substitute sensitive data with a token and match it to original only when needed.</td>
</tr><tr><td><li><a href="https://docs.cossacklabs.com/acra/security-controls/key-management/">Basic key management tools</a></li></td><td>built-in tools for key generation, export, backup, rotation, etc.</td>
</tr><tr><td><li><a href="https://docs.cossacklabs.com/acra/security-controls/sql-firewall/">Prevention of SQL injections</a></li></td><td>through a built-in SQL firewall.</td>
</tr><tr><td><li><a href="https://docs.cossacklabs.com/acra/security-controls/intrusion-detection/">Intrusion detection</a></li></td><td> using poison records (honey tokens) to warn about suspicious behaviour.</td>
</tr><tr><td><li><a href="https://docs.cossacklabs.com/acra/security-controls/key-management/operations/rotation/">Key rotation without data re-encryption</a> ᵉ </li></td><td rowspan=3>available for <a href="https://www.cossacklabs.com/acra/#pricing" target="_blank">Acra Enterprise</a> users.</td>
</tr><tr><td><li><a href="https://docs.cossacklabs.com/acra/configuring-maintaining/key-storing/kms-integration/">KMS support</a> ᵉ </li></td>
</tr><tr><td><li><a href="https://docs.cossacklabs.com/acra/security-controls/security-logging-and-events/audit-logging/">Cryptographically protected audit log</a> ᵉ </li></td>
</tr></tbody></table>

Acra delivers different layers of defense for different parts and stages of the data lifecycle. This is what **defence in depth** is – an independent set of security controls aimed at mitigating multiple risks in case of an attacker crossing the outer perimeter. 

### API form factors

<table><tbody>
<tr><td><li> <a href="https://docs.cossacklabs.com/acra/acra-in-depth/architecture/acraserver/" target=_blank>AcraServer</a>: transparent SQL proxy </li></td><td> all Acra features packed into a database proxy that parses traffic between an app and a database and applies security functions where appropriate. </td></tr>
<tr><td><li> <a href="https://docs.cossacklabs.com/acra/acra-in-depth/architecture/acratranslator/" target=_blank>AcraTranslator</a>: HTTP/gRPC encryption API </li></td><td> API server, that exposes most of Acra’s features as HTTP / gRPC API. </td></tr>
<tr><td><li> <a href="https://docs.cossacklabs.com/acra/security-controls/transport-security/acra-connector/" target=_blank>AcraConnector</a>: transport authentication and encryption </li></td><td> optional client-side service for authentication and transport encryption.</td></tr>
<tr><td><li> <a href="https://docs.cossacklabs.com/acra/acra-in-depth/architecture/anyproxy/" target=_blank>AnyProxy</a>: use Acra with any database / datastore via SDK ᵉ </li></td><td rowspan=5>available for <a href="https://www.cossacklabs.com/acra/#pricing" target="_blank">Acra Enterprise</a> users.</td></tr>
<tr><td><li> <a href="https://docs.cossacklabs.com/acra/acra-in-depth/architecture/sdks/acrawriter/" target=_blank>AcraWriter</a>: SDK for client-side encryption ᵉ</li></td>
<tr><td><li> <a href="https://docs.cossacklabs.com/acra/acra-in-depth/architecture/sdks/acrareader/" target=_blank>AcraReader</a>: SDK for client-side decryption ᵉ</li></td></tr>
<tr><td><li> <a href="https://docs.cossacklabs.com/acra/acra-in-depth/architecture/sdks/acratranslator-sdk/" target=_blank>SDK for AcraTranslator</a>: client-side SDK that encapsulates AcraTranslator's API ᵉ </li></td></tr>
<tr><td><li> <a href="https://docs.cossacklabs.com/acra/guides/integrating-acra-translator-into-new-infrastructure/http_api/#bulk-processing-api-enterprise" target=_blank>Bulk API for AcraTranslator</a> ᵉ </li></td></tr>
</tbody></table>

### Developer and DevOps friendly

<table><tbody>
<tr><td><li> Secure default settings </li></td><td> your infrastructure is secure from the start without additional configuring. </td></tr>
<tr><td><li> Cryptography is hidden<br/>under the hood </li></td><td> no risk of selecting the wrong key length or algorithm padding. </td></tr>
<tr><td><li> Automation-friendly </li></td><td> easy to configure and automate. </td></tr>
<tr><td><li> Quick infrastructure integration </li></td><td> via binary packages or Docker images. </td></tr>
<tr><td><li> Easy client-side integration</li></td><td> requires minimal changes in the application code. </td></tr>
<tr><td><li> <a href="https://docs.cossacklabs.com/acra/security-controls/security-logging-and-events/" target=_blank>Logging, metrics, tracing<a> </li></td><td> throughout all Acra components;<br/>compatible with ELK stack, Prometheus, Jaeger. </td></tr>
<tr><td><li> No vendor lock </li></td><td> rollback utilities to decrypt database into plaintext. </td></tr>
<tr><td><li> <a href="https://github.com/cossacklabs/acra-engineering-demo" targert=_blank>Demos and examples</li></td><td> numerous web-based and Docker-based example projects available. </td></tr>
<tr><td><li> <a href="https://marketplace.digitalocean.com/apps/acra?action=deploy" target="_blank">DigitalOcean Acra 1-Click App</a> </li></td><td> run AcraServer in your DigitalOcean cloud. </td></tr>
<tr><td><li> Managed solution available</li></td><td> we can <a href="https://www.cossacklabs.com/acra/#pricing" target="_blank">setup and manage Acra</a> for you. </td></tr>
</tbody></table>

## Cryptography

Acra relies on our cryptographic library [Themis](https://www.cossacklabs.com/themis/), which implements high-level cryptosystems based on the best available [open-source implementations](https://docs.cossacklabs.com/themis/crypto-theory/cryptography-donors/) of the [most reliable ciphers](https://docs.cossacklabs.com/themis/architecture/soter/). Acra strictly doesn't contain self-made cryptographic primitives or obscure ciphers. 

To deliver its unique guarantees, Acra relies on the combination of well-known ciphers and smart key management scheme. See [Cryptography and key management](https://docs.cossacklabs.com/acra/acra-in-depth/cryptography-and-key-management/).

<table><tbody>
<tr><td> Default crypto-primitive source </td><td> OpenSSL </td></tr>
<tr><td> Supported crypto-primitive sources ᵉ<td> BoringSSL, LibreSSL, FIPS-compliant, GOST-compliant, HSM</td></tr>
<tr><td> Storage encryption (<a href="https://docs.cossacklabs.com/acra/acra-in-depth/data-structures/acrablock/" target=_blank>AcraBlocks</a>) </td><td> AES-256-GCM + AES-256-GCM </td></tr>
<tr><td> Storage encryption (<a href="https://docs.cossacklabs.com/acra/acra-in-depth/data-structures/acrastruct/" target=_blank>AcraStructs</a>) </td><td> AES-256-GCM + ECDH </td></tr>
<tr><td> <a href="https://docs.cossacklabs.com/acra/security-controls/transport-security/" target=_blank>Transport encryption</a> </td><td> TLS v1.2+ or Themis Secure Session </td></tr>
<tr><td> <a href="https://docs.cossacklabs.com/acra/acra-in-depth/architecture/key-storage-and-kms/" target=_blank>KMS integration</a> ᵉ</td><td> Amazon KMS, Google Cloud Platform KMS, HashiCorp Vault, Keywhiz, etc </td></tr>
</tbody></table>

ᵉ — available in the [Enterprise version of Acra](https://www.cossacklabs.com/acra/#pricing/) only. [Drop us an email](mailto:sales@cossacklabs.com) to get a full list of features and a quote.

## Try Acra without writing code

[Acra Example Projects](https://github.com/cossacklabs/acra-engineering-demo) illustrate the integration of Acra data protection suite into existing applications: web applications based on Django and Ruby on Rails frameworks, and simple CLI applications. We took well-known apps, detected sensitive data there and added the encryption layer. Protecting the data is completely transparent for the users and requires minimal changes in the infrastructure and application code.

<img src="https://github.com/cossacklabs/acra/wiki/Images/readme/AcraEngDemo.png" width="600">
 
Developers and Ops friendly:
* run a single command to deploy the application, database, Acra's components, logs, and dashboards;
* read the code changes and see how little it takes to integrate encryption into the client application;
* learn how Acra works by reading logs, monitoring metrics in Prometheus, checking tracers in Jaeger and watching Grafana dashboards;
* inspect Docker-compose files, architecture schemes, database tables, and much more.

Requirements: Linux or macOS with installed Docker.

| ⚙️ [Run Acra Example Projects](https://github.com/cossacklabs/acra-engineering-demo) ⚙️ |
|---|

<!-- PLs update me -->

## How does Acra work?

To better understand the architecture and data flow in Acra, please refer to the [Architecture](https://docs.cossacklabs.com/acra/acra-in-depth/architecture/) section in the documentation.

### Protecting data in SQL databases using AcraServer

AcraServer works as transparent encryption/decryption proxy with SQL databases. Depending on your app architecture, it's possible to use client-side encryption or server-side encryption, or both simultaneously.

#### Integrating client-side encryption using AcraWriter

<p align="center"><img src="https://github.com/cossacklabs/acra/wiki/Images/readme/acra-server-acra-writer.png" alt="Client-side encryption using AcraServer and AcraWriter" width="1600"></p>

_The typical infrastructure with AcraConnector and AcraServer, data is encrypted on the client side (web backend or mobile app) using AcraWriter, decrypted on the AcraServer side, that works as transparent database proxy._

<p align="center"><img src="https://github.com/cossacklabs/acra/wiki/Images/readme/AcraArchi-Readme.png" alt="Client-side encryption using AcraServer and AcraWriter" width="400"></p>

_The dataflow of encrypted and plaintext data. Note: it's possible to write encrypted data directly to the database, omitting the AcraServer._

This is what the process of encryption and decryption of data in a database looks like:

- Your application encrypts some data through [**AcraWriter**](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter) by generating an [**AcraStruct**](https://docs.cossacklabs.com/pages/documentation-acra/#acrastruct) using Acra storage public key and then updates the database. AcraStructs generated by AcraWriter can't be decrypted by it — only the Acra's server side has the keys for decryption.    
- To retrieve the decrypted data, your application talks to [**AcraServer**](https://docs.cossacklabs.com/pages/documentation-acra/#server-side-acraserver). It is a server-side service that works as a database proxy: it transparently sits between your application and the database and silently listens to all the traffic coming to and from the database.     
- AcraServer monitors the incoming SQL requests and blocks the unwanted ones using the built-in configurable SQL firewall called [**AcraCensor**](https://docs.cossacklabs.com/pages/documentation-acra/#acracensor-acra-s-firewall). AcraServer only sends allowed requests to the database. Certain configurations for AcraServer can be adjusted remotely using [**AcraWebConfig**](https://docs.cossacklabs.com/pages/documentation-acra/#acrawebconfig) web server.    
- Upon receiving the database response, AcraServer tries to detect AcraStructs, decrypts them, and returns the decrypted data to the application.    
- AcraConnector is a client-side daemon responsible for providing encrypted and authenticated connection between the application and AcraServer. [**AcraConnector**](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter) runs under a separate user/in a separate container and acts as middleware. AcraConnector accepts connections from the application, adds an extra transport encryption layer using TLS or [Themis Secure Session](http://docs.cossacklabs.com/pages/secure-session-cryptosystem/), sends the data to AcraServer, receives the result, and sends it back to the application.

#### Integrating proxy-side encryption using AcraServer in Transparent proxy mode

<p align="center"><img src="https://github.com/cossacklabs/acra/wiki/Images/readme/acra-server-proxy.png" alt="Server-side encryption using AcraServer" width="1600"></p>

_The typical infrastructure with AcraConnector and AcraServer, data is encrypted and decrypted by AcraServer, that works as transparent database proxy._

<p align="center"><img src="https://github.com/cossacklabs/acra/wiki/Images/readme/AcraArchi-TransparentMode-Readme-2.png" alt="Server-side encryption using AcraServer" width="200"></p>

_The dataflow of encrypted and plaintext data, AcraServer it encrypts and decrypts data._

[Transparent proxy mode](https://docs.cossacklabs.com/pages/documentation-acra/#transparent-proxy-mode) allows you to configure [**AcraServer**](https://docs.cossacklabs.com/pages/documentation-acra/#server-side-acraserver) to encrypt records in specific database columns without altering the application code. Basically, AcraServer here performs AcraWriter's duties. 

This mode is useful for large distributed applications, where separate updating of the source code for each client app is complicated.

- Imagine that the client application wants to update some data in the database. The application logic doesn't need to change because there's no need to integrate AcraWriter library into the application code. The application sends SQL requests with plaintext data through [**AcraConnector**](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter) and AcraServer to the database, as described above. There's a secure transport layer between AcraConnector and AcraServer (via TLS or Themis Secure Session), so data from client app is transmitted via a secure channel.
- On receiving SQL queries, AcraServer parses each query and encrypts the desired values into [**AcraStructs**](https://docs.cossacklabs.com/pages/documentation-acra/#acrastruct). To know which values to encrypt, AcraServer uses a special configuration file (known as `encryptor_config_file`) that describes which columns in which tables should be encrypted. AcraServer uses AcraStruct encryption key just as AcraWriter would.
- After encrypting the values into AcraStructs, AcraServer passes the modified queries to the database and the database response – back to the client application via AcraConnector.
- When the client application wants to read the data, it sends a read query to the database (via AcraConnector and AcraServer). Upon retrieving the database response, AcraServer tries to detect AcraStructs, decrypts them, and returns the decrypted data to the application.

Transparent mode has the same features as the "usual" mode – including SQL firewall, intrusion detection based on poison records, Zone support, etc.

Check out the [detailed documentation](https://docs.cossacklabs.com/pages/documentation-acra/#transparent-proxy-mode) on using and configuring the Transparent proxy mode.

### Protecting data in any file storage using AcraWriter and AcraTranslator

<p align="center"><img src="https://github.com/cossacklabs/acra/wiki/Images/readme/acra-translator.png" alt="Client-side encryption and standalone decryption using AcraTranslator" width="700"></p>

_The typical infrastructure with AcraConnector and AcraTranslator, data is encrypted on the client side (web backend or mobile app) using AcraWriter, decrypted on the AcraTranslator side, that works as standalone decryption service._

<p align="center"><img src="https://github.com/cossacklabs/acra/wiki/Images/readme/AcraArchi-AT-Readme.png" alt="Acra Translator: simplified architecture" width="500"></p>

_The dataflow of encrypted and plaintext data, AcraTranslator only decrypts data on demand._

In some use cases, the application can store encrypted data as separate blobs (in NoSQL databases, or as files that are not in a database, i.e. in a S3 bucket, local file storage, etc.). In this case, you can use [**AcraTranslator**](http://docs.cossacklabs.com/pages/acratranslator/) — a lightweight server that receives [**AcraStructs**](https://docs.cossacklabs.com/pages/documentation-acra/#acrastruct) and returns the decrypted data.

**Note:** since Q3 2020, AcraTranslator can both encrypt and decrypt data via REST API (HTTP, gRPC). You may use a combination of AcraWriter+AcraTranslator for client-side encryption and Translator-side decryption; or AcraTranslator only for both encryption and decryption without changing app code.

This is what the process of encryption and decryption of data using AcraTranslator looks like:

- Your application encrypts some data using [**AcraWriter**](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter), generating an AcraStruct using Acra storage public key and puts the data into any file storage. AcraStructs generated by AcraWriter can't be decrypted by it — only the Acra's server side has the right keys for decrypting it. Otherwise, you might decide not to use AcraWriter, but use AcraTranslator for encrypting data – application sends plaintext, AcraTranslator returns AcraStructs.
- To decrypt an AcraStruct, your application sends it to [**AcraTranslator**](http://docs.cossacklabs.com/pages/acratranslator/) as a binary blob via HTTP or gRPC API. AcraTranslator doesn’t care about the source of the data, it is responsible for holding all the secrets required for data decryption and for actually decrypting the data.     
- AcraTranslator decrypts AcraStructs and returns the decrypted data to the application.       
- To avoid sending plaintext via an unsecured channel, AcraTranslator requires the use of [**AcraConnector**](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter), a client-side daemon responsible for providing encrypted and authenticated connection between the application and AcraServer. AcraConnector runs under a separate user/in a separate container and acts as middleware. It accepts connections from the application, adds transport encryption layer using TLS or [Themis Secure Session](http://docs.cossacklabs.com/pages/secure-session-cryptosystem/), sends data to AcraServer, receives the result, and sends it back to the application.

AcraTranslator and AcraServer are fully independent server-side components and can be used together or separately depending on your infrastructure.

## Availability

### Compatibility and integration

Acra is a suite of components, most of them are "server-side", meaning that you deploy and configure AcraServer, AcraTranslator or AnyProxy, and connect your client-side application to them. 

Acra components are compatible with numerous RDBMS, object and KV stores, cloud platforms, external key management systems (KMS), load balancing systems.

<table><tbody>
<tr><td> Cloud platforms </td><td> DigitalOcean, AWS, GCP, Heroku, any </td></tr>
<tr><td> RDBMS </td><td> MySQL v5.7+, PosgtreSQL v9.4-v11, MariaDB v10.3;<br/> Google Cloud SQL, Amazon RDS </td></tr>
<tr><td> Object stores </td><td> filesystems, KV databases, Amazon S3, Google Cloud DataStore </td></tr>
<tr><td> Load balancing </td><td> HAProxy, cloud balancers </td></tr>
<tr><td> Server-side platforms </td><td> Ubuntu, Debian, CentOS, RHEL;<br/>Docker </td></tr>
<tr><td> Client-side app language </td><td> any :) </td></tr>
</tbody></table>

Open source Acra has a limited integration support, more services are available in the [Acra Enterprise Edition](https://www.cossacklabs.com/acra/#pricing) only.

### Server-side

The server-side Acra components (AcraServer, AcraTranslator, AnyProxy) should run on separate servers/VMs for better isolation and compartmentalization. Key management utils and database helpers are usually run on the same server as AcraServer, AcraTranslator, AnyProxy.

The server-side Acra components run on most Linux distributives (Ubuntu, Debian, CentOS) and as Docker images. Note, the server-side Acra components are not compatible with Windows OS as host OS, consider using Docker.

See [Getting started](https://docs.cossacklabs.com/acra/getting-started/) to learn how to [install Acra](https://docs.cossacklabs.com/acra/getting-started/installing/) or to [try Acra without coding](https://docs.cossacklabs.com/acra/getting-started/trying/).

### Client-side

Acra works with any client applications. No matter what languages you use to write your apps, you can connect them to AcraServer (via SQL) and AcraTranslator/AnyProxy (via API) to encrypt, decrypt, tokenise and mask the data.

Acra provides a set of client-side SDKs which are useful only in specific use cases:

- <a href="https://docs.cossacklabs.com/acra/acra-in-depth/architecture/sdks/acrawriter/" target=_blank>AcraWriter</a> – SDK to encrypt data fields into AcraStructs. Use it when encrypting data on the app side is important (for building end-to-end encrypted dataflows or working in hostile environments).
- <a href="https://docs.cossacklabs.com/acra/acra-in-depth/architecture/sdks/acrareader/" target=_blank>AcraReader</a> – SDK to decrypt data fields from AcraStructs. Use it when decrypting data on the app side is important (for building end-to-end encrypted dataflows or working in hostile environments).
- <a href="https://docs.cossacklabs.com/acra/acra-in-depth/architecture/sdks/acratranslator-sdk/" target=_blank>SDK for AcraTranslator</a> – SDK that encapsulates AcraTranslator's API for more convenient usage.

These SDKs are available for Ruby, Python, Go, C++, Node.js, iOS (Swift, ObjC), Android (Java, Kotlin), desktop Java and PHP.

## Installation and launch

See [Getting started](https://docs.cossacklabs.com/acra/getting-started/) to learn how to [install Acra](https://docs.cossacklabs.com/acra/getting-started/installing/) or to [try Acra without coding](https://docs.cossacklabs.com/acra/getting-started/trying/).


## Documentation and tutorials

The most recent versions of the documentation, tutorials, and demos for Acra are available on the official [Cossack Labs Documentation Server](https://docs.cossacklabs.com/acra/).

To gain an initial understanding of Acra, you might want to:

- [What is Acra](https://docs.cossacklabs.com/acra/what-is-acra/) to get an overview of things.
- Acra's [security controls](https://docs.cossacklabs.com/acra/security-controls/) to learn more about encryption, masking, tokenisation, SQL firewall, intrusion detections, etc.
- Typical [dataflows](https://docs.cossacklabs.com/acra/acra-in-depth/data-flow/) that shows which Acra components you need and what are the Pros and Cons of each combination.
- Read the notes on Acra's [architecture](https://docs.cossacklabs.com/acra/acra-in-depth/architecture/) and [security design](https://docs.cossacklabs.com/acra/acra-in-depth/security-design/) to understand better what you get when you use Acra and what is the threat model that Acra operates in.

You can also check out the speaker slides for the following talks by Cossack Labs engineers:
- ["Encryption Without Magic, Risk Management Without Pain"](https://speakerdeck.com/vixentael/encryption-without-magic-risk-management-without-pain) by [Anastasiia Voitova](https://github.com/vixentael).
- ["Data encryption for Ruby web applications"](https://speakerdeck.com/shad/data-encryption-for-ruby-web-applications) by [Dmytro Shapovalov](https://github.com/shadinua).
- ["Building SQL firewall(AcraCensor): insights from developers"](https://speakerdeck.com/storojs72/building-sql-firewall-insights-from-developers) by [Artem Storozhuk](https://github.com/storojs72).

## Demo projects

| ⚙️ [Run Acra Example Projects](https://github.com/cossacklabs/acra-engineering-demo) ⚙️ |
|---|

## GDPR, HIPAA, CCPA

Acra can help you comply with the current privacy regulations, such as:
* [General Data Protection Regulation (GDPR)](https://gdpr-info.eu/)   
* [HIPAA (Health Insurance Portability and Accountability Act)](https://en.wikipedia.org/wiki/Health_Insurance_Portability_and_Accountability_Act)        
* [DPA (Data Protection Act)](http://www.legislation.gov.uk/ukpga/2018/12/contents/enacted)     
* [CCPA (California Consumer Privacy Act)](https://en.wikipedia.org/wiki/California_Consumer_Privacy_Act)    

Configuring and using Acra in a designated form will cover most of the demands described in articles 25, 32, 33, and 34 of GDPR and the PII data protection demands of HIPAA. Read more about [Acra and Regulations](https://docs.cossacklabs.com/acra/regulations/).

## Open source vs Enterprise

This is Acra Community Edition, the open source version of Acra, which is 💯 free for commercial and non-commercial usage. Please let us know in the [Issues](https://www.github.com/cossacklabs/acra/issues) if you stumble upon a bug, see a possible enhancement, or have a comment on security design.

There are also [Acra Enterprise Edition](https://www.cossacklabs.com/acra/#pricing) available. It provides better performance, redundancy/load balancing, comes pre-configured with crypto-primitives of your choice (FIPS, GOST), has integration with key/secret management tools in your stack, policy management, client-side SDKs, and have plenty of utils and tools for your Ops and SREs to operate Acra conveniently. [Talk to us](mailto:sales@cossacklabs.com) to get full feature lists and a quote.

## Security consulting

It takes more than just getting cryptographic code to compile to secure the sensitive data. Acra won't make you “compliant out of the box” with all the modern security regulations, and no other tool will.

[We help companies](https://www.cossacklabs.com/solutions/security-strategy-advisory/) plan their data security strategy by auditing, assessing data flow, and classifying the data, enumerating the risks. We do the hardest, least-attended part of reaching the compliance – turning it from the “cost of doing business” into the “security framework that prevents risks”.


## Contributing to us

If you’d like to contribute your code or provide any other kind of input to Acra, you’re very welcome. Your starting point for contributing [is here](https://docs.cossacklabs.com/acra/contributing-and-community/).


## License

Acra Community Edition is licensed as Apache 2 open-source software.


## Contacts

If you want to ask a technical question, feel free to raise an [Issue](https://github.com/cossacklabs/acra/issues) or write to [dev@cossacklabs.com](mailto:dev@cossacklabs.com).

To talk to the business wing of Cossack Labs Limited, drop us an email to [info@cossacklabs.com](mailto:info@cossacklabs.com).
   
[![Blog](https://img.shields.io/badge/blog-cossacklabs.com-7a7c98.svg)](https://cossacklabs.com/) [![Twitter CossackLabs](https://img.shields.io/badge/twitter-cossacklabs-fbb03b.svg)](https://twitter.com/cossacklabs) [![DEV CossackLabs](https://img.shields.io/badge/devto-%40cossacklabs-black.svg)](https://dev.to/cossacklabs/) [![Medium CossackLabs](https://img.shields.io/badge/medium-%40cossacklabs-orange.svg)](https://medium.com/@cossacklabs/)
