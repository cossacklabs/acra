<h3 align="center">
  <a href="https://www.cossacklabs.com/acra/"><img src="https://github.com/cossacklabs/acra/wiki/Images/acralogo.png" alt="Acra: database security suite" width="420"></a>
  <br>
  Database protection suite with selective encryption and intrusion detection.
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
</p>
<br>

| [Acra Live Demo](https://www.cossacklabs.com/acra/#acralivedemo) | [Acra Engineering Demo](https://github.com/cossacklabs/acra-engineering-demo) | [Documentation](https://docs.cossacklabs.com/products/acra/) | [Installation](https://github.com/cossacklabs/acra#installation-and-launch) | [Examples and tutorials](https://github.com/cossacklabs/acra#documentation-and-tutorials) |
| ---- | ---- | ---- | --- | --- |


## What is Acra
Acra — database security suite for sensitive and personal data protection.

Acra provides selective encryption, multi-layered access control, database leakage prevention, and intrusion detection capabilities in a convenient, developer-friendly package. Acra was specifically designed for web and mobile apps with centralised data storage, including with distributed, microservice-rich applications.

<table><thead><tr><th>Perfect Acra-compatible applications</th>
<th>Typical industries</th></tr></thead>
<tbody><tr><td>Web and mobile apps that store data in a centralised database or object storage</td>
<td rowspan=3><ul>
<li>Healthcare</li>
<li>Finance</li>
<li>E-commerce</li>
<li>Critical infrastructures</li>
<li>Apps with > 1000 users</li></ul></td>
</tr><tr><td>IoT apps that collect telemetry and process data in cloud</td>
</tr><tr><td>High-load data processing apps</td>
</tr></tbody></table>

Acra gives you tools for encrypting the data on the application's side into special [cryptographic containers](https://docs.cossacklabs.com/pages/documentation-acra/#acrastruct), storing them in the database or file storage, and then decrypting them in a secure compartmented area (separate virtual machine/container). 

Cryptographic design ensures that no secret (password, key, etc.) leaked from the application or database will be sufficient for decryption of the protected data chunks that originate from it. Acra minimises the leakage scope, detects unauthorised behavior, and prevents the leakage, informing operators of the incident underway.

This is [Acra Community Edition](https://www.cossacklabs.com/acra/#pricing), it's free for commercial and non-commercial usage, forever.

### Major security features

<table><tbody><tr><tr><td><li>Cryptographic protection of data </li></td><td> during storage and transmission </td>
</tr><tr><td><li>Selective encryption </li></td><td> protect only the sensitive data to have both good security and performance </td>
</tr><tr><td><li>Key management tools </li></td><td> built-in tools for key distribution, key rotation, and compartmentalisation</td>
</tr><tr><td><li>Trust compartmentalisation </li></td><td> datastore and application components can be compromised, yet the data is protected</td>
</tr><tr><td><li>Prevention of SQL injections </li></td><td> through a built-in SQL firewall </td>
</tr><tr><td><li>Intrusion detection system </li></td><td> to give an early warning about suspicious behaviour </td>
</tr><tr><td><li>Searchable encryption ᵉ </li></td><td>available for <a href="https://www.cossacklabs.com/acra/#pricing" target="_blank">Acra Enterprise</a> users</td>
</tr><tr><td><li>Pseudonymisation </li></td><td rowspan=2> <i>coming in the (near) future releases</i>
</tr><tr><td><li>Cryptographically protected audit log </li></td>
</tr></tbody></table>

Acra delivers different layers of defense for different parts and stages of the data lifecycle. This is what **defence in depth** is – an independent set of security controls aimed at mitigating multiple risks in case of an attacker crossing the outer perimeter. 

### Developer and DevOps friendly

<table><tbody>
<tr><td><li> Secure default settings </li></td><td> your infrastructure is secure from the start without additional configuring </td></tr>
<tr><td><li> Cryptography is hidden<br/>under the hood </li></td><td> no risk of selecting the wrong key length or algorithm padding </td></tr>
<tr><td><li> Automation-friendly </li></td><td> easy to configure and automate </td></tr>
<tr><td><li> Quick infrastructure integration </li></td><td> via binary packages or Docker images </td></tr>
<tr><td><li> Easy client-side integration </li></td><td> client-side encryption libraries support ~11 languages </td></tr>
<tr><td><li> Code-less client-side integration </li></td><td> server-side encryption in AcraServer's Transparent proxy mode</td></tr>
<tr><td><li> Logging, metrics, tracing </li></td><td> throughout all Acra components;<br/>compatible with ELK stack, Prometheus, Jaeger </td></tr>
<tr><td><li> No vendor lock </li></td><td> rollback utilities to decrypt database into plaintext </td></tr>
<tr><td><li> Demos, examples and simulators </li></td><td> numerous web-based and Docker-based example projects </td></tr>
<tr><td><li> Managed solution available</li></td><td> we can <a href="https://www.cossacklabs.com/acra/#pricing" target="_blank">setup and manage Acra</a> for you </td></tr>
</tbody></table>

## Cryptography

Acra relies on our cryptographic library [Themis](https://www.cossacklabs.com/themis/), which implements high-level cryptosystems based on the best available [open-source implementations](https://docs.cossacklabs.com/pages/themis-cryptographic-donors/) of the [most reliable ciphers](https://docs.cossacklabs.com/pages/soter/). Acra strictly doesn't contain self-made cryptographic primitives or obscure ciphers. To deliver its unique guarantees, Acra relies on the combination of well-known ciphers and smart key management scheme.

<table><tbody>
<tr><td> Default crypto-primitive source </td><td> OpenSSL </td></tr>
<tr><td> Supported crypto-primitive sources ᵉ<td> BoringSSL, LibreSSL, FIPS-compliant, GOST-compliant, HSM</td></tr>
<tr><td> Storage encryption </td><td> AES-256-GCM + ECDH </td></tr>
<tr><td> Transport encryption </td><td> TLS v1.2+ / Themis Secure Session </td></tr>
<tr><td> KMS integration ᵉ</td><td> Amazon KMS, Google Cloud Platform KMS, Hashicorp Vault, Keywhiz </td></tr>
</tbody></table>

ᵉ — available in the [Enterprise version of Acra](https://www.cossacklabs.com/acra/#pricing/) only. [Drop us an email](mailto:sales@cossacklabs.com) to get a full list of features and a quote.


## Try Acra without writing code

### Acra Live Demo (see Acra in action in one click)

[Acra Live Demo](https://acra.cossacklabs.com/) is a web-based demo of protecting data in a typical web-infrastructure (deployed on our servers for your convenience).

<img src="https://github.com/cossacklabs/acra/wiki/Images/readme/AcraLiveDemo.png" width="600">
Acra Live Demo infrastructure contains: Django-based application, PostgreSQL database, AcraServer with AcraCensor, log monitor. Sensitive data is encrypted in a Django application, stored in a database, and decrypted through Acra. 

From the users' perspective, the website's work is unchanged. However, the data is securely protected so that even hacking the web application won't lead to data leakage.

The available actions include:
* adding new rows to the database (in plaintext and encrypted form);
* watching the database content change in real-time;
* running malicious SQL queries that will be [blocked by AcraCensor](https://docs.cossacklabs.com/pages/documentation-acra/#acracensor-acra-s-firewall);
* [rolling back](https://docs.cossacklabs.com/pages/acrarollback/) the encrypted data;
* [intrusion detection](http://docs.cossacklabs.com/pages/intrusion-detection/).

Requirements: Chrome, Firefox, or Safari browser.

> Note: We create separate playground for each user, that's why we ask for your email; you'll receive the invitation link.

| 🖥 [Request Acra Live Demo](https://www.cossacklabs.com/acra/#acralivedemo) 🖥 |
|---|


## How does Acra work?

To better understand the architecture and data flow in Acra, please refer to the [Architecture and data flow](https://docs.cossacklabs.com/pages/documentation-acra/#architecture-and-data-flow) section in the documentation.

### Protecting data in SQL databases using AcraWriter and AcraServer

<p align="center"><img src="https://docs.cossacklabs.com/files/wiki/acrawriter-acraserver-SQL.png" alt="Acra Server: simplified architecture" width="500"></p>

This is what the process of encryption and decryption of data in a database looks like:

- Your application encrypts some data through [**AcraWriter**](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter) by generating an [**AcraStruct**](https://docs.cossacklabs.com/pages/documentation-acra/#acrastruct) using Acra storage public key and then updates the database. AcraStructs generated by AcraWriter can't be decrypted by it — only the Acra's server side has the keys for decryption.    
- To retrieve the decrypted data, your application talks to [**AcraServer**](https://docs.cossacklabs.com/pages/documentation-acra/#server-side-acraserver). It is a server-side service that works as database proxy: it sits transparently between your application and the database and listens silently to all the traffic that's coming to and from the database.     
- AcraServer monitors the incoming SQL requests and blocks the unwanted ones using the built-in configurable firewall called [**AcraCensor**](https://docs.cossacklabs.com/pages/documentation-acra/#acracensor-acra-s-firewall). AcraServer only sends allowed requests to the database. Certain configurations for AcraServer can be adjusted remotely using [**AcraWebConfig**](https://docs.cossacklabs.com/pages/documentation-acra/#acrawebconfig) web server.    
- Upon receiving the database response, AcraServer tries to detect the AcraStructs, decrypts them, and returns the decrypted data to the application.    
- AcraConnector is a client-side daemon responsible for providing encrypted and authenticated connection between the application and AcraServer. [**AcraConnector**](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter) runs under a separate user/in a separate container and acts as middleware. AcraConnector accepts connections from the application, adds an extra transport encryption layer using TLS or [Themis Secure Session](http://docs.cossacklabs.com/pages/secure-session-cryptosystem/), sends the data to AcraServer, receives the result, and sends it back to the application.

### Protecting data in any file storage using AcraWriter and AcraTranslator

<p align="center"><img src="https://docs.cossacklabs.com/files/wiki/acrawriter-acratranslator-elsewhere.png" alt="Acra Translator: simplified architecture" width="500"></p>

In some use cases, the application can store encrypted data as separate blobs (files that are not in a database, i.e. in a S3 bucket, local file storage, etc.). In this case, you can use [**AcraTranslator**](http://docs.cossacklabs.com/pages/acratranslator/) — a lightweight server that receives [**AcraStructs**](https://docs.cossacklabs.com/pages/documentation-acra/#acrastruct) and returns the decrypted data.

This is what the process of encryption and decryption of data using AcraTranslator looks like:

- Your application encrypts some data using [**AcraWriter**](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter), generating an AcraStruct using Acra storage public key and puts the data into any file storage. AcraStructs generated by AcraWriter can't be decrypted by it — only the Acra's server side has the right keys for decrypting it.     
- To decrypt an AcraStruct, your application sends it to [**AcraTranslator**](http://docs.cossacklabs.com/pages/acratranslator/) as a binary blob via HTTP or gRPC API. AcraTranslator doesn’t care about the source of the data, it is responsible for holding all the secrets required for data decryption and for actually decrypting the data.     
- AcraTranslator decrypts AcraStructs and returns the decrypted data to the application.       
- To avoid sending plaintext via an unsecured channel, AcraTranslator requires the use of [**AcraConnector**](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter), a client-side daemon responsible for providing encrypted and authenticated connection between the application and AcraServer. AcraConnector runs under a separate user/in a separate container and acts as middleware. It accepts connections from the application, adds transport encryption layer using TLS or [Themis Secure Session](http://docs.cossacklabs.com/pages/secure-session-cryptosystem/), sends data to AcraServer, receives the result, and sends it back to the application.

AcraTranslator and AcraServer are fully independent server-side components and can be used together or separately depending on your infrastructure.

## Availability

### Client-side

[AcraWriter](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter) is a client-side library that encrypts data into a special binary format called [AcraStruct](https://docs.cossacklabs.com/pages/documentation-acra/#acrastruct). AcraWriter is available for Ruby, Python, Go, C++, Node.js, iOS, Android/Java and PHP, but you can easily [generate AcraStruct containers](https://github.com/cossacklabs/acra/wiki/Acrawriter-installation) with [Themis](https://github.com/cossacklabs/themis) for any platform you want. 

| Client platform |  Documentation and guides | Examples | Package manager |
| :----- | :----- | :------ | :---- |
| 🐹 Go | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-go) | [examples/golang](https://github.com/cossacklabs/acra/tree/master/examples/golang) ||
| 🐍 Python | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-python) | [examples/python](https://github.com/cossacklabs/acra/tree/master/examples/python) | [![PyPI](https://img.shields.io/pypi/v/acrawriter.svg)](https://pypi.org/project/acrawriter/) |
| ♦️ Ruby | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-ruby) | [examples/ruby](https://github.com/cossacklabs/acra/tree/master/examples/ruby) | [![Gem](https://img.shields.io/gem/v/acrawriter.svg)](https://rubygems.org/gems/acrawriter) |
| ➕ C++ | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-c-) | [examples/cpp](https://github.com/cossacklabs/acra/tree/master/examples/cpp) ||
| 📱 Objective-C / Swift (iOS) | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-ios) | [examples/objc](https://github.com/cossacklabs/acra/tree/master/examples/objc) | [![CocoaPods](https://img.shields.io/cocoapods/v/acrawriter.svg)](https://cocoapods.org/pods/acrawriter) |
| ☎️ Java (Android) | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-android) | [examples/android_java](https://github.com/cossacklabs/acra/tree/master/examples/android_java) |[ ![maven](https://api.bintray.com/packages/cossacklabs/maven/acrawriter/images/download.svg) ](https://bintray.com/cossacklabs/maven/acrawriter/_latestVersion)|
| 🐘 PHP | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-php) | [examples/php](https://github.com/cossacklabs/acra/tree/master/examples/php) ||
| 🍭 Javascript (Node.js) | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-nodejs) | [examples/nodejs](https://github.com/cossacklabs/acra/tree/master/examples/nodejs) | [![npm](https://img.shields.io/npm/v/acrawriter.svg)](https://www.npmjs.com/package/acrawriter) |

### Server-side

* The Server-side Acra components should run as separate services/servers. 
* There are three possible ways to install and launch Acra components in your infrastructures:
  - [download and run our Docker-based demo stand](https://docs.cossacklabs.com/pages/trying-acra-with-docker/) to deploy all you need using a single command.
  - [download pre-built Acra binaries](https://docs.cossacklabs.com/pages/documentation-acra/#installing-acra-from-the-cossack-labs-repository) for supported distributives.
  - [build from sources](https://docs.cossacklabs.com/pages/documentation-acra/#installing-from-github) (Acra is built and tested with Go versions 1.9.7 – 1.11).
  
* Acra binaries are built for: 

| Distributive | Instruction set | Download and install |
|---------------| ------| ------|
| CentOS 7 | x86_64 | [using rpm packages](https://docs.cossacklabs.com/pages/documentation-acra/#centos-rhel-oel) |
| Debian Stretch (9)<br/> Debian Jessie (8) | x86_64/i386 | [using deb packages](https://docs.cossacklabs.com/pages/documentation-acra/#debian-ubuntu)|
| Ubuntu Bionic (18.04) | x86_64 | [using deb packages](https://docs.cossacklabs.com/pages/documentation-acra/#debian-ubuntu)||
| Ubuntu Artful (17.10)<br/> Ubuntu Xenial (16.04)<br/>Ubuntu Trusty (14.04)| x86_64/i386 | [using deb packages](https://docs.cossacklabs.com/pages/documentation-acra/#debian-ubuntu)| |

### Compatibility and integration

AcraServer is a server-side service that works as database proxy: it sits transparently between your application and the database, listens silently to all the traffic that's coming to and from the database. AcraTranslator is database-agnostic: it provides HTTP and gRPC API to decrypt AcraStructs stored anywhere.

Acra is compatible with numerous RDBMS, object and KV stores, cloud platforms, external key management systems (KMS), load balancing systems.

<table><tbody>
<tr><td> Cloud platforms </td><td> AWS, GCP, Heroku </td></tr>
<tr><td> RDBMS </td><td> MySQL v5.7+, PosgtreSQL v9.4-v11, MariaDB v10.3<br/> Google Cloud SQL, Amazon RDS </td></tr>
<tr><td> Object stores </td><td> filesystems, KV databases, Amazon S3, Google Cloud DataStore </td></tr>
<tr><td> Load balancing </td><td> HAProxy, cloud balancers </td></tr>
</tbody></table>

Open source Acra has limited integration support, more services are available in the [Enterprise version of Acra](https://www.cossacklabs.com/acra/#pricing) only.

## Installation and launch

### Quick try (run example apps)

[Acra Example Projects](https://github.com/cossacklabs/acra-engineering-demo) illustrate the integration of Acra data protection suite into existing applications: web applications based on Django and Ruby on Rails frameworks, and simple CLI applications. We took well-known apps, detected sensitive data there and added the encryption layer. Protecting the data is completely transparent for the users and requires minimal changes in the infrastructure and application code.

<img src="https://github.com/cossacklabs/acra/wiki//Images/readme/AcraEngDemo.png" width="600">
 
Developers and Ops friendly:
* run a single command to deploy the application, database, Acra's components, logs, and dashboards;
* read the code changes and see how little it takes to integrate encryption into the client application;
* learn how Acra works by reading logs, monitoring metrics in Prometheus, checking tracers in Jaeger and watching Grafana dashboards;
* inspect Docker-compose files, architecture schemes, database tables, and much more.

Requirements: Linux or macOS with installed Docker.

| ⚙️ [Run Acra Example Projects](https://github.com/cossacklabs/acra-engineering-demo) ⚙️ |
|---|

### Quick integration into your infrastructure

For a quick and easy integration of Acra into your own infrastructure, we recommend [trying Acra with Docker](http://docs.cossacklabs.com/pages/trying-acra-with-docker/) first. Using only two commands, you will get all the Acra's components and database up and running, with a secure transport layer between them. We prepared several typical infrastructure variants to experiment with.

* Select one appropriate use case from the [pre-made configurations](https://docs.cossacklabs.com/pages/trying-acra-with-docker/) ("Compose files"): use AcraServer-based configuration to protect the data in a database or select AcraTranslator to protect the files or any other binary blob stored elsewhere.     
* Launch Acra's server-side by running the selected docker-compose file: it will generate the appropriate keys, put them into correct folders, perform a public key exchange, run selected services and database, and then it will listen to the incoming connections.    
* Integrate [AcraWriter](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter) into your application code where you need to protect the sensitive data, supply AcraWriter with an Acra storage public key (generated by docker-compose on the previous step). Encrypt the data into AcraStructs and send them into the database or file storage.     
* Decrypt data by reading the database through AcraServer or by decrypting the files through AcraTranslator.    

Please use the Acra Docker demo stand for testing/experimenting purposes only as the encryption keys are pre-generated in the configuration.

### Normal integration into your infrastructure

For production environments, we insist on generating and exchanging keys manually and deploying Acra as Docker containers or from source code. Refer to the [Quick Start guide](https://docs.cossacklabs.com/pages/documentation-acra/#installing-acra-from-the-cossack-labs-repository) to understand how to download and launch Acra components, generate keys, and perform key exchange properly.

## Documentation, tutorials, additional information

The most recent version of the documentation, tutorials, and demos for Acra is available on the official [Cossack Labs Documentation Server](https://docs.cossacklabs.com/products/acra/). The Github Wiki documentation is deprecated and no longer updated since v0.82.0.

To gain an initial understanding of Acra, you might want to:

- Read about using the lightweight [HTTP web server AcraWebConfig](https://docs.cossacklabs.com/pages/documentation-acra/#acrawebconfig) we provide to manage AcraServer configuration in a simple fashion.
- Read the notes on [security design](https://docs.cossacklabs.com/pages/security-design/) and [intrusion detection](https://docs.cossacklabs.com/pages/intrusion-detection/) to better understand what you get when you use Acra and what is the threat model that Acra operates in. 
- Key and trust management tools: [key distribution](https://docs.cossacklabs.com/pages/documentation-acra/#key-management), [key rotation](https://docs.cossacklabs.com/pages/acrarotate/) and [database rollback](https://docs.cossacklabs.com/pages/acrarollback/).
- Set up [rules for AcraCensor (SQL firewall)](https://doc-staging.dev.cossacklabs.com/pages/documentation-acra/#acracensor-acra-s-firewall) suitable for your application.
- Read [some notes on making Acra stronger, more productive, and efficient](https://docs.cossacklabs.com/pages/tuning-acra/) and about adding security features or increasing throughput, depending on your goals and security model.
- Read about the [logging format](https://docs.cossacklabs.com/pages/documentation-acra/#logging-in-acra) that Acra supports if you are using a SIEM system.    

You can also check out the speaker slides for the following talks by Cossack Labs engineers:
- ["Encryption Without Magic, Risk Management Without Pain"](https://speakerdeck.com/vixentael/encryption-without-magic-risk-management-without-pain) by [Anastasiia Voitova](https://github.com/vixentael).
- ["Data encryption for Ruby web applications"](https://speakerdeck.com/shad/data-encryption-for-ruby-web-applications) by [Dmytro Shapovalov](https://github.com/shadinua).
- ["Building SQL firewall(AcraCensor): insights from developers"](https://speakerdeck.com/storojs72/building-sql-firewall-insights-from-developers) by [Artem Storozhuk](https://github.com/storojs72).

## Demo projects

| [Django sample project](https://github.com/cossacklabs/djangoproject.com) | [RubyGems sample project](https://github.com/cossacklabs/rubygems.org) |
| --- | --- |

### AcraCensor Example (SQL firewall in action)

[AcraCensor Demo](https://github.com/cossacklabs/acra-censor-demo) is an example project that illustrates how to use [AcraCensor](https://docs.cossacklabs.com/pages/documentation-acra/#acracensor-acra-s-firewall) as SQL firewall to prevent SQL injections. The target application is a well-known vulnerable web application [OWASP Mutillidae 2](https://github.com/webpwnized/mutillidae). 

The demo project has a Docker compose file that runs the following web infrastructure:    

- OWASP Mutillidae web application,         
- Acra encryption suite.  

Acra works as a proxy between web and database. AcraCensor inspects every SQL query that runs from the web application to the database, and back, and blocks suspicious queries.

<a href="https://youtu.be/ABjIfx2_hJk" target="_blank"><img src="https://docs.cossacklabs.com/files/wiki/YouTube-Screencast-AcraCensor.png" alt="Watch the video" width="700"></a>

Requirements: Linux or macOS with installed Docker.

| ⚙️ [Run AcraCensor SQL firewall example](https://github.com/cossacklabs/acra-censor-demo) ⚙️ |
|---|

### Acra Load Balancing Example (HAProxy-based infrastructures)

[Acra Load Balancing Example](https://github.com/cossacklabs/acra-balancer-demo) illustrates building high availability and balanced infrastructure, based on Acra components, PostgreSQL, and Python web application. We prepared several configurations with multiple databases and HAProxy.

| 🔛 [Run Acra Load Balancing Example](https://github.com/cossacklabs/acra-balancer-demo) 🔛 |
|---|

## GDPR and HIPAA

Acra can help you comply with GDPR and HIPAA regulations. Configuring and using Acra in a designated form will cover most of the demands described in articles 25, 32, 33, and 34 of GDPR and the PII data protection demands of HIPAA. Read more about [Acra and GDPR compliance here](http://docs.cossacklabs.com/pages/acra-and-gdpr-compliance/).

## Open source vs Pro vs Enterprise

This is Acra Community Edition, the open source version of Acra, which is 💯 free for commercial and non-commercial usage. Please let us know in the [Issues](https://www.github.com/cossacklabs/acra/issues) if you stumble upon a bug, see a possible enhancement, or have a comment on security design.

There are also [Pro and Enterprise versions of Acra](https://www.cossacklabs.com/acra/#pricing) available. Those versions provide better performance, redunancy/load balancing, come pre-configured with crypto-primitives of your choice (FIPS, GOST), integrate with key/secret management tools in your stack, and have plenty of utils and tools for your Ops and SREs to operate Acra conveniently – deployment automation, scaling, monitoring, and logging. [Talk to us](mailto:sales@cossacklabs.com) to get full feature lists and a quote.

## Security consulting

It takes more than just getting cryptographic code to compile to secure the sensitive data. Acra won't make you “compliant out of the box” with all the modern security regulations, and no other tool will. 

[We help companies](https://www.cossacklabs.com/dgap/) plan their data security strategy by auditing, assessing data flow, and classifying the data, enumerating the risks. We do the hardest, least-attended part of reaching the compliance – turning it from the “cost of doing business” into the “security framework that prevents risks”.


## Contributing to us

If you’d like to contribute your code or provide any other kind of input to Acra, you’re very welcome. Your starting point for contributing [is here](https://docs.cossacklabs.com/pages/documentation-acra/#contributing-to-acra).


## License

Acra is licensed as Apache 2 open-source software.


## Contacts

If you want to ask a technical question, feel free to raise an [Issue](https://github.com/cossacklabs/acra/issues) or write to [dev@cossacklabs.com](mailto:dev@cossacklabs.com).

To talk to the business wing of Cossack Labs Limited, drop us an email to [info@cossacklabs.com](mailto:info@cossacklabs.com).
   
[![Blog](https://img.shields.io/badge/blog-cossacklabs.com-7a7c98.svg)](https://cossacklabs.com/) [![Twitter CossackLabs](https://img.shields.io/badge/twitter-cossacklabs-fbb03b.svg)](http://twitter.com/cossacklabs) [![Medium CossackLabs](https://img.shields.io/badge/medium-%40cossacklabs-orange.svg)](https://medium.com/@cossacklabs/)


