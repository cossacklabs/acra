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
  <a href="https://github.com/cossacklabs/acra/releases/latest"><img src="https://img.shields.io/badge/Client%20Platforms-Go%20%7C%20Ruby%20%7C%20Python%20%7C%20PHP%20%7C%20NodeJS%20%7C%20iOS%20%7C%20Android-green.svg" alt="Client platforms"></a>
</p>
<br>


| [Documentation](https://docs.cossacklabs.com/products/acra/) | [Acra Live Demo](https://www.cossacklabs.com/acra/#acralivedemo) | [Python sample project](https://github.com/cossacklabs/djangoproject.com) | [Ruby sample project](https://github.com/cossacklabs/rubygems.org) | [Examples](https://github.com/cossacklabs/acra/tree/master/examples) |
| ---- | ---- | ---- | --- | --- |

## What is Acra
Acra — database security suite for sensitive and personal data protection.

Acra provides selective encryption, multi-layered access control, database leakage prevention, and intrusion detection capabilities in a convenient, developer-friendly package. Acra was specifically designed for web and mobile apps with centralised data storage, including with distributed, microservice-rich applications.

Acra gives you tools for encrypting the data on the application's side into special [cryptographic containers](https://github.com/cossacklabs/acra/wiki/AcraStruct), storing them in the database or file storage, and then decrypting them in a secure compartmented area (separate virtual machine/container). 

Cryptographic design ensures that no secret (password, key, etc.) leaked from the application or database will be sufficient for decryption of the protected data chunks that originate from it. 

Acra was built with specific user experiences in mind: 

- **Quick and straightforward integration** of security instrumentation.
- **Easy to try**: you can experience the full might of Acra without committing to its installation using [Docker containers](https://docs.cossacklabs.com/pages/trying-acra-with-docker/) (you can also request access to [Acra Live Demo](https://www.cossacklabs.com/acra/#acralivedemo) to play around with Acra without installing a thing).
- **Compatibility with encryption-demanding compliances**: Acra can run on certified crypto-libraries (FIPS, GOST).
- **Cryptographic protection of data**: to compromise an Acra-powered app, the attacker will need to compromise a separate compartmented server, AcraServer - more specifically - its key storage and database; until AcraServer is compromised, the data is safe.
- **Cryptography is hidden under the hood**: you're safe from the risk of selecting a wrong key length or algorithm padding.
- **Secure default settings** to get you going. 
- **Intrusion detection** to give you an early warning about suspicious behaviour.
- **SQL injections prevention** through a built-in SQL firewall.
- **Ops-friendly**: Acra can be easily configured and automated using a configuration automation environment.


Acra is a continuously developing security tool. And as any proper security tool, it requires enormous human efforts for validation of the methods, code, and finding possible infrastructural weaknesses. We're constantly enhancing and improving Acra as we go. This is done to ensure that the provided security benefits are not rendered useless through implementation problems or increased complexity.

## Cryptography

Acra relies on our cryptographic library [Themis](https://www.cossacklabs.com/themis/), which implements high-level cryptosystems based on the best available [open-source implementations](https://docs.cossacklabs.com/pages/themis-cryptographic-donors/) of the [most reliable ciphers](https://docs.cossacklabs.com/pages/soter/). Acra does not contain any self-made cryptographic primitives or obscure ciphers. To deliver its unique guarantees, Acra relies on the combination of well-known ciphers and a smart key management scheme.

The [enterprise version of Acra](https://www.cossacklabs.com/acra/) can run on the certified crypto-libraries of your choice (i.e. the abovementioned FIPS, GOST, etc.), [drop us an email](mailto:sales@cossacklabs.com) to get a quote.


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

Requirements: Chrome, Firefox or Safari browser.

> Note: We create separate playground for each user, that's why we ask for your email; you'll receive the invitation email.

| 🖥 [Access Live Demo](https://www.cossacklabs.com/acra/#acralivedemo) 🖥 |
|---|

### Acra Engineering Demo (deploy the whole infrastructure in one command)

[Acra Engineering Demo](https://github.com/cossacklabs/acra-engineering-demo) illustrates the integration of Acra data protection suite into existing applications: Django-based web application and python CLI application. We took well-known applications and added the encryption layer.

<img src="https://github.com/cossacklabs/acra/wiki//Images/readme/AcraEngDemo.png" width="600">
Protecting the data is completely transparent for the users and requires minimal changes in the infrastructure.
 
Developers and Ops friendly:
* run a single command to deploy the application, database, Acra's components, logs, and dashboards;
* read the code changes and see how little it takes to integrate encryption into the client application;
* learn how Acra works by reading logs, monitoring metrics in Prometheus, and watching Grafana dashboards;
* inspect Docker-compose files, architecture schemes, database tables, and much more.

Requirements: Linux or macOS terminal.

| ⚙️ [Run Engineering Demo](https://github.com/cossacklabs/acra-engineering-demo) ⚙️ |
|---|

## Availability

### Client-side

[AcraWriter](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter) is a client-side library that encrypts data into a special binary format called [AcraStruct](https://docs.cossacklabs.com/pages/documentation-acra/#acrastruct). AcraWriter is available for Ruby, Python, Go, NodeJS, iOS, Android/Java and PHP, but you can easily [generate AcraStruct containers](https://github.com/cossacklabs/acra/wiki/Acrawriter-installation) with [Themis](https://github.com/cossacklabs/themis) for any platform you want. 

| Client platform |  Documentation and guides | Examples |
| :----- | :----- | :------ |
| 🐹 Go | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-go) | [examples/golang](https://github.com/cossacklabs/acra/tree/master/examples/golang) |
| 🐍 Python | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-python) | [examples/python](https://github.com/cossacklabs/acra/tree/master/examples/python) |
| ♦️ Ruby | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-ruby) | [examples/ruby](https://github.com/cossacklabs/acra/tree/master/examples/ruby) |
| 📱 Objective-C / Swift (iOS) | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-ios) | [examples/objc](https://github.com/cossacklabs/acra/tree/master/examples/objc) |
| ☎️ Java (Android) | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-android) | [examples/android_java](https://github.com/cossacklabs/acra/tree/master/examples/android_java) |
| 🐘 PHP | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-php) | [examples/php](https://github.com/cossacklabs/acra/tree/master/examples/php) |
| 🍭 Javascript (NodeJS) | [Installation guide](https://docs.cossacklabs.com/pages/documentation-acra/#building-acrawriter-for-nodejs) | [examples/nodejs](https://github.com/cossacklabs/acra/tree/master/examples/nodejs) |

### Server-side

* The Server-side Acra components should run as a separate services/servers. 
* There are three possible ways to install and launch Acra components:
  - [download and run our Docker-based demo stand](https://docs.cossacklabs.com/pages/trying-acra-with-docker/) to deploy all you need using a single command (read more about it below).
  - [download pre-built Acra binaries](https://docs.cossacklabs.com/pages/documentation-acra/#installing-acra-from-the-cossack-labs-repository) for supported distributives (see list below).
  - [build from sources](https://docs.cossacklabs.com/pages/documentation-acra/#installing-from-github) (Acra is built and tested with Go versions 1.8 – 1.10).
  
* Acra binaries are built for: 

| Distributive | Instruction set | Download and install |
|---------------| ------| ------|
| CentOS 7 | x86_64 | [using rpm](https://docs.cossacklabs.com/pages/documentation-acra/#centos-rhel-oel) |
| Debian Stretch (9)<br/> Debian Jessie (8) | x86_64/i386 | [using apt-get](https://docs.cossacklabs.com/pages/documentation-acra/#debian-ubuntu)|
| Ubuntu Bionic (18.04) | x86_64 | [using apt-get](https://docs.cossacklabs.com/pages/documentation-acra/#debian-ubuntu)||
| Ubuntu Artful (17.10)<br/> Ubuntu Xenial (16.04)<br/>Ubuntu Trusty (14.04)| x86_64/i386 |[using apt-get](https://docs.cossacklabs.com/pages/documentation-acra/#debian-ubuntu)| |

### Database requirements

AcraServer is a server-side service that works as database proxy: it sits transparently between your application and the database, listens silently to all the traffic that's coming to and from the database. 

Supported databases:

| RDBMS | Version |
|--------| ------|
| MySQL | 5.7+ |
| PostgreSQL | 9.4+ |

## How does Acra work?

To better understand the architecture and data flow, please refer to [Architecture and data flow](https://docs.cossacklabs.com/pages/documentation-acra/#architecture-and-data-flow) section in the documentation.

### Protecting data in SQL databases using AcraWriter and AcraServer

<p align="center"><img src="https://docs.cossacklabs.com/files/wiki/acrawriter-acraserver-SQL.png" alt="Acra Server: simplified architecture" width="500"></p>

This is what the process of encryption and decryption of the data in a database looks like:

- Your application encrypts some data through [**AcraWriter**](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter) by generating an [**AcraStruct**](https://docs.cossacklabs.com/pages/documentation-acra/#acrastruct) using Acra storage public key and then updates the database. AcraStructs generated by AcraWriter can't be decrypted by it — only the Acra's server side has the right keys for decryption.    
- To retrieve the decrypted data, your application talks to [**AcraServer**](https://docs.cossacklabs.com/pages/documentation-acra/#server-side-acraserver). It is a server-side service that works as database proxy: it sits transparently between your application and the database, listens silently to all the traffic that's coming to and from the database.     
- AcraServer monitors the incoming SQL requests and blocks the unwanted ones using the built-in configurable firewall called [**AcraCensor**](https://docs.cossacklabs.com/pages/documentation-acra/#acracensor-acra-s-firewall). AcraServer only sends allowed requests to the database. Certain configurations for AcraServer can be adjusted remotely using [**AcraWebConfig**](https://docs.cossacklabs.com/pages/documentation-acra/#acrawebconfig) web server.    
- Upon receiving the database response, AcraServer tries to detect the AcraStructs, decrypts them, and returns the decrypted data to the application.    
- AcraConnector is a client-side daemon responsible for providing encrypted and authenticated connection between the application and AcraServer. [**AcraConnector**](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter) runs under a separate user/in a separate container and acts as middleware. AcraConnector accepts connections from the application, adds an extra transport encryption layer using TLS or [Themis Secure Session](http://docs.cossacklabs.com/pages/secure-session-cryptosystem/), sends the data to AcraServer, receives the result, and sends it back to the application.

### Protecting data in any file storage using AcraWriter and AcraTranslator

<p align="center"><img src="https://docs.cossacklabs.com/files/wiki/acrawriter-acratranslator-elsewhere.png" alt="Acra Translator: simplified architecture" width="500"></p>

In some use cases, the application can store encrypted data as separate blobs (files that are not in a database, i.e. in a S3 bucket, local file storage, etc.). In this case, you can use [**AcraTranslator**](http://docs.cossacklabs.com/pages/acratranslator/) — a lightweight server that receives [**AcraStructs**](https://docs.cossacklabs.com/pages/documentation-acra/#acrastruct) and returns the decrypted data.

This is what the process of encryption and decryption data using AcraTranslator looks like:

- Your application encrypts some data using [**AcraWriter**](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter), generating an AcraStruct using Acra storage public key and puts the data into any file storage. AcraStructs generated by AcraWriter can't be decrypted by it — only the Acra's server side has the right keys for decrypting it.     
- To decrypt an AcraStruct, your application sends it to [**AcraTranslator**](http://docs.cossacklabs.com/pages/acratranslator/) as a binary blob via HTTP or gRPC API. AcraTranslator doesn’t care about the source of the data, it is responsible for holding all the secrets required for data decryption and for actually decrypting the data.     
- AcraTranslator decrypts AcraStructs and returns the decrypted data to the application.       
- To avoid sending the plaintext via an unsecured channel, AcraTranslator requires the use of [**AcraConnector**](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter), a client-side daemon responsible for providing encrypted and authenticated connection between the application and AcraServer. AcraConnector runs under a separate user/in a separate container and acts as a middleware. It accepts connections from the application, adds transport encryption layer using TLS or [Themis Secure Session](http://docs.cossacklabs.com/pages/secure-session-cryptosystem/), sends data to AcraServer, receives the result, and sends it back to the application.

AcraTranslator and AcraServer are fully independent server-side components and can be used together or separately depending on your infrastructure.

## Installation and launch

### Quick launch

For a quick and easy start, we recommend [trying Acra with Docker](http://docs.cossacklabs.com/pages/trying-acra-with-docker/) first. Using only two commands, you will get all the Acra's components and database up and running, with a secure transport layer between them. We prepared several typical infrastructure variants to experiment with.

* Select one appropriate use case from the [pre-made configurations](https://docs.cossacklabs.com/pages/trying-acra-with-docker/) ("Compose files"): use AcraServer-based configuration to protect the data in a database or select AcraTranslator to protect the files or any other binary blob stored elsewhere.     
* Launch Acra's server-side by running the selected docker-compose file: it will generate the appropriate keys, put them into correct folders, perform a public key exchange, run selected services and database, and then it will listen to the incoming connections.    
* Integrate [AcraWriter](https://docs.cossacklabs.com/pages/documentation-acra/#client-side-acraconnector-and-acrawriter) into your application code where you need to protect the sensitive data, supply AcraWriter with an Acra storage public key (generated by docker-compose on the previous step). Encrypt the data into AcraStructs and send them into the database or file storage.     
* Decrypt data by reading the database through AcraServer or by decrypting the files through AcraTranslator.    

Please use the Acra Docker demo stand for testing/experimenting purposes only as the encryption keys are pre-generated in the configuration.

### Manual launch

For production environments, we insist on generating and exchanging keys manually. Refer to the [Quick Start guide](https://docs.cossacklabs.com/pages/documentation-acra/#installing-acra-from-the-cossack-labs-repository) to understand how to download and launch Acra components, generate keys, and perform a key exchange properly.


## Additionally

The most recent version of the documentation, tutorials, and demos for Acra is available in the official [Cossack Labs Documentation Server](https://docs.cossacklabs.com/products/acra/). The Wiki documentation is deprecated and no longer updated since 0.82.0.

To gain an initial understanding of Acra, you might want to:

- Read about using the lightweight [HTTP web server AcraWebConfig](https://docs.cossacklabs.com/pages/documentation-acra/#acrawebconfig) we provide to manage AcraServer configuration in a simple fashion.
- Read the notes on [security design](https://docs.cossacklabs.com/pages/security-design/) and [intrusion detection](https://docs.cossacklabs.com/pages/intrusion-detection/) to better understand what you get when you use Acra and what is the threat model that Acra operates in. 
- Read [some notes on making Acra stronger, more productive, and efficient](https://docs.cossacklabs.com/pages/tuning-acra/) and about adding security features or increasing throughput, depending on your goals and security model.
- Read about the [logging format](https://docs.cossacklabs.com/pages/documentation-acra/#logging-in-acra) that Acra supports if you are using a SIEM system.


## GDPR and HIPAA

Acra can help you comply with GDPR and HIPAA regulations. Configuring and using Acra in a designated form will cover most demands described in articles 25, 32, 33 and 34 of GDPR, and PII data protection demands from HIPAA. Read more about [Acra and GDPR compliance here](http://docs.cossacklabs.com/pages/acra-and-gdpr-compliance/).

## Open source vs Enterprise

This open source version of Acra is free to use. Please let us know in the [Issues](https://www.github.com/cossacklabs/acra/issues) if you stumble upon a bug, see a possible enhancement, or have a comment on security design.

There’s a [commercial version of Acra](https://www.cossacklabs.com/acra/) available. It provides better performance, redunancy/load balancing, comes pre-configured with crypto-primitives of your choice (FIPS, GOST), integrates with key/secret management tools in your stack, and has plenty of goodies for your Ops and SREs to operate Acra conveniently – deployment automation, scaling, monitoring, and logging. [Talk to us](mailto:sales@cossacklabs.com) if you're interested.

## Security consulting

It takes more than just getting cryptographic code to compile to secure the sensitive data. Acra won't make you “compliant out of the box” and no other tool will. 

[We help companies](https://www.cossacklabs.com/dgap/) to plan their data security strategy by auditing, assessing data flow, and classifying the data, enumerating the risks. We do the hardest, least-attended part of compliance – turning it from the “cost of doing business” into the “security framework that prevents risks”.


## Contributing to us

If you’d like to contribute your code or provide any other kind of input to Acra, you’re very welcome. Your starting point for contributing [is here](https://docs.cossacklabs.com/pages/documentation-acra/#contributing-to-acra).


## License

Acra is licensed as Apache 2 open-source software.


## Contacts

If you want to ask a technical question, feel free to raise an [Issue](https://github.com/cossacklabs/acra/issues) or write to [dev@cossacklabs.com](mailto:dev@cossacklabs.com).

To talk to the business wing of Cossack Labs Limited, drop us an email to [info@cossacklabs.com](mailto:info@cossacklabs.com).
   
[![Blog](https://img.shields.io/badge/blog-cossacklabs.com-7a7c98.svg)](https://cossacklabs.com/) [![Twitter CossackLabs](https://img.shields.io/badge/twitter-cossacklabs-fbb03b.svg)](http://twitter.com/cossacklabs) [![Medium CossackLabs](https://img.shields.io/badge/medium-%40cossacklabs-orange.svg)](https://medium.com/@cossacklabs/)


