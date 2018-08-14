<h3 align="center">
  <a href="https://www.cossacklabs.com"><img src="https://github.com/cossacklabs/acra/wiki/Images/acra_web.jpg" alt="Acra: transparent database encryption server" width="500"></a>
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
  <a href="https://github.com/cossacklabs/acra/releases/latest"><img src="https://img.shields.io/badge/Client%20Platforms-Go%20%7C%20Ruby%20%7C%20Python%20%7C%20PHP%20%7C%20NodeJS-green.svg" alt="Client platforms"></a>
</p>
<br>


|[Documentation](https://github.com/cossacklabs/acra/wiki) | [Python sample project](https://github.com/cossacklabs/djangoproject.com) | [Ruby sample project](https://github.com/cossacklabs/rubygems.org) | [Examples](https://github.com/cossacklabs/acra/tree/master/examples) |
| ---- | ---- | ---- | --- |

## What is Acra

Acra brings encryption and data leakage prevention to distributed applications, web and mobile apps with database backends. Acra provides selective encryption, multi-layered access control, database leakage prevention and intrusion detection capabilities in a convenient, developer-friendly package.

Acra gives you tools for encrypting the data on the application's side into a special [cryptographic container](https://github.com/cossacklabs/acra/wiki/AcraStruct), storing it in the database or file storage, and then decrypting it in a secure compartmented area (separate virtual machine/container). 

Cryptographic design ensures that no secret (password, key, anything) leaked from the application or database will be sufficient for decryption of the protected data chunks that originate from it. 

Acra was built with specific user experiences in mind: 

- **quick and easy integration** of security instrumentation;
- **easy to try**: you can experience the full might of Acra without commiting to its installation using [Docker containers](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker);
- **compatible with encryption-demanding compliance**, Acra can run on certified crypto-libraries (FIPS, GOST);
- **cryptographic protection of data**: to compromise an Acra-powered app, an attacker will need to compromise a separate compartmented server, AcraServer - more specifically - its key storage and database, until that the data is safe.
- **cryptography is hidden under the hood**: you're safe from the risk of selecting the wrong key length or algorithm padding;
- **secure default settings** to get you going; 
- **intrusion detection** to let you know early that something wrong is going on;
- **SQL injections prevention** by built-in SQL firewall;
- **ops-friendly**: Acra can be easy configured and automated using a configuration automation environment.


Acra is a continuously developing security tool. And as any proper security tool, it requires enourmous human efforts for validation of the methods, code, and finding possible infrastructural weaknesses. Although we do run Acra in production in several instances, we're constantly enhancing and improving it as we go. This is done to ensure that the provided security benefits are not rendered useless through implementation problems or increased complexity.

## Cryptography

Acra relies on our cryptographic library [Themis](https://www.github.com/cossacklabs/themis), which implements high-level cryptosystems based on the best available [open-source implementations](https://github.com/cossacklabs/themis/wiki/Cryptographic-donors) of the [most reliable ciphers](https://github.com/cossacklabs/themis/wiki/Soter). Acra does not contain any self-made cryptographic primitives or obscure ciphers. Instead, to deliver its unique guarantees, Acra relies on the combination of well-known ciphers and smart key management scheme.

## Availability

### Client-side

[AcraWriter](https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter#acrawriter) is a client-side library that encrypts data into a special binary format called [AcraStruct](https://github.com/cossacklabs/acra/wiki/AcraStruct). AcraWriter is available for Ruby, Python, Go, NodeJS, iOS and PHP, but you can easily [generate AcraStruct containers](https://github.com/cossacklabs/acra/wiki/Acrawriter-installation) with [Themis](https://github.com/cossacklabs/themis) for any platform you want. 

| Client platform |  Documentation and guides | Examples |
| :----- | :----- | :------ |
| 🐹 Go | [Installation guide](https://github.com/cossacklabs/acra/wiki/AcraWriter-installation#golang) | [examples/golang](https://github.com/cossacklabs/acra/tree/master/examples/golang) |
| 🐍 Python | [Installation guide](https://github.com/cossacklabs/acra/wiki/AcraWriter-installation#python) | [examples/python](https://github.com/cossacklabs/acra/tree/master/examples/python) |
| ♦️ Ruby | [Installation guide](https://github.com/cossacklabs/acra/wiki/AcraWriter-installation#ruby) | [examples/ruby](https://github.com/cossacklabs/acra/tree/master/examples/ruby) |
| 📱 Objective-C (iOS) | [Installation guide](https://github.com/cossacklabs/acra/wiki/AcraWriter-installation#ios) | [examples/objc](https://github.com/cossacklabs/acra/tree/master/examples/objc) |
| 🐘 PHP | [Installation guide](https://github.com/cossacklabs/acra/wiki/AcraWriter-installation#php) | [examples/php](https://github.com/cossacklabs/acra/tree/master/examples/php) |
| 🍭 Javascript (NodeJS) | [Installation guide](https://github.com/cossacklabs/acra/wiki/AcraWriter-installation#nodejs) | [examples/nodejs](https://github.com/cossacklabs/acra/tree/master/examples/nodejs) |

### Server-side

* Server-side Acra components should run as a separate services/servers. 
* There are three possible ways to install and launch Acra components:
  - [download and run Docker containers](https://github.com/cossacklabs/acra/wiki/Quick-start-guide#using-acra-with-docker-the-recommended-way), or use our Docker-based demo stand to deploy all you need using one command.
  - [download pre-built Acra binaries](https://github.com/cossacklabs/acra/wiki/Quick-start-guide#installing-acra-from-the-cossack-labs-repository) for supported distributives (see list below).
  - [build from sources](https://github.com/cossacklabs/acra/wiki/Quick-start-guide#installing-from-github---install-acraserver) (Acra is built and tested with Go versions 1.8 – 1.10).
  
* Acra binaries are built for: 

| Distributive | Instruction set | Download and install |
|---------------| ------| ------|
| CentOS 7 | x86_64 | [using rpm](https://github.com/cossacklabs/acra/wiki/Quick-start-guide#centos--rhel--oel) |
| Debian Stretch (9)<br/> Debian Jessie (8) | x86_64/i386 | [using apt-get](https://github.com/cossacklabs/acra/wiki/Quick-start-guide#debian--ubuntu)|
| Ubuntu Bionic (18.04) | x86_64 | [using apt-get](https://github.com/cossacklabs/acra/wiki/Quick-start-guide#debian--ubuntu)||
| Ubuntu Artful (17.10)<br/> Ubuntu Xenial (16.04)<br/>Ubuntu Trusty (14.04)| x86_64/i386 |[using apt-get](https://github.com/cossacklabs/acra/wiki/Quick-start-guide#debian--ubuntu)| |

### Database requirements

AcraServer is a server-side service that works as database proxy: it sits transparently between your application and the database, listens silently to all the traffic that's coming to and from the database. 

Supported databases:

| RDBMS | Version |
|--------| ------|
| MySQL | 5.7+ |
| PostgreSQL | 9.4+ |


## How does Acra work?

To better understand the architecture and data flow, please refer to [Architecture and data flow](https://github.com/cossacklabs/acra/wiki/Architecture-and-data-flow) section in the official documentation.

### Protecting data in SQL databases with AcraWriter and AcraServer

<p align="center"><img src="https://raw.githubusercontent.com/wiki/cossacklabs/acra/Images/readme/AcraArchi-Readme.png" alt="Acra Server: simplified architecture" width="500"></p>

This is how the process of encryption and decryption data in a database looks like:

- Your application encrypts some data using [**AcraWriter**](https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter), generating [**AcraStruct**](https://github.com/cossacklabs/acra/wiki/AcraStruct) using Acra storage public key, and updates the database. AcraStructs generated by AcraWriter can't be decrypted by it — only the Acra server side has the right keys to decrypt it.
- To retrieve decrypted data, your application talks to [**AcraServer**](https://github.com/cossacklabs/acra/wiki/How-AcraServer-works). It is a server-side service that works as database proxy: it sits transparently between your application and the database, listens silently to all the traffic that's coming to and from the database. 
- AcraServer monitors incoming SQL requests and blocks unwanted ones by built-in configurable firewall called [**AcraCensor**](https://github.com/cossacklabs/acra/wiki/acracensor).  AcraServer sends only allowed requests to the database. Certain configurations for AcraServer can be adjusted remotely using [**AcraWebConfig**](https://github.com/cossacklabs/acra/wiki/AcraWebConfig) web server.
- Upon receiving the database response, AcraServer tries to detect the AcraStructs, decrypts them and returns decrypted data to the application.
- There is also [**AcraConnector**](https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter), a client-side daemon, that is responsible for providing encrypted and authenticated connection between application and AcraServer. AcraConnector runs under a separate user / in a separate container, and acts as a middleware. It accepts connections from application, adds extra transport encryption layer using [Themis Secure Session](https://github.com/cossacklabs/themis/wiki/Secure-Session-cryptosystem), sends data to AcraServer, receives result and sends it back to application. AcraConnector is a optional component and can be replaced with TLS v1.2/1.3, however Themis Secure Session provides better security guaranties 'out of the box' than average TLS configuration found in a wild.

### Protecting data in any file storage with AcraWriter and AcraTranslator

<p align="center"><img src="https://raw.githubusercontent.com/wiki/cossacklabs/acra/Images/readme/AcraArchi-AT-Readme.png" alt="Acra Translator: simplified architecture" width="500"></p>

Depending on use-case your application can store encrypted data as separate blobs (files that are not in a database - i.e. in the S3 bucket, local file storage, etc.). You might use [**AcraTranslator**]() is a lightweight server that receives [**AcraStruct**](https://github.com/cossacklabs/acra/wiki/AcraStruct) and returns the decrypted data.

This is how the process of encryption and decryption data using AcraTranslator looks like:

- Your application encrypts some data using [**AcraWriter**](https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter), generating AcraStruct using Acra storage public key, and puts data to any file storage. AcraStructs generated by AcraWriter can't be decrypted by it — only the Acra server side has the right keys to decrypt it.
- To decrypt AcraStruct your application sends it to [**AcraTranslator**](https://github.com/cossacklabs/acra/wiki) as binary blob via HTTP or gRPC API. AcraTranslator doesn’t care about the source of the data, it is responsible for holding all the secrets required for data decryption and for actually decrypting the data.
- AcraTranslator decrypts AcraStructs and returns decrypted data to the application.
- To avoid sending plaintext via unsecured channel, AcraTranslator requires the use of [**AcraConnector**](https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter), a client-side daemon, that is responsible for providing encrypted and authenticated connection between application and AcraServer. AcraConnector runs under a separate user / in a separate container, and acts as a middleware. It accepts connections from application, adds extra transport encryption layer using [Themis Secure Session](https://github.com/cossacklabs/themis/wiki/Secure-Session-cryptosystem), sends data to AcraServer, receives result and sends it back to application. AcraConnector is a optional component and can be replaced with TLS v1.2/1.3, however Themis Secure Session provides better security guaranties 'out of the box' than average TLS configuration found in a wild.

AcraTranslator and AcraServer are fully independent server-side components and can be used together or separately depending on your infrastructure.

## 4 steps to start

* Read the [Quick start guide](https://github.com/cossacklabs/acra/wiki/Quick-start-guide) to install launch all the components. We suggest trying [Acra with Docker](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker) as a way to deploy all Acra demo stand using one command.
* Deploy server-side component: either [AcraServer](https://github.com/cossacklabs/acra/wiki/Quick-start-guide) or [AcraTranslator](https://github.com/cossacklabs/acra/wiki/) on a separate server. 
* [Generate the keys](https://github.com/cossacklabs/acra/wiki/Key-Management): transport keypairs and storage keypair.
* Deploy [AcraConnector](https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter#acraconnector) on each server where you need to read sensitive data. Generate AcraConnector transport keypair and exchange public keys: put AcraConnector transport public key to AcraServer/AcraTranslator key storage, and put AcraServer/AcraTranslator transport public key into AcraConnector key storage. User AcraConnector address as your database address and access it as your normal database installation.
* Integrate [AcraWriter](https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter#acrawriter) into your code where you need to store sensitive data, supply AcraWriter with a Acra storage public key to encrypt data. Generate AcraStructs from you application and put them into database or file storage. Perform read requests to database and get decrypted data.

## Additionally

We fill and update the [Wiki documentation](https://github.com/cossacklabs/acra/wiki) with useful articles about the core Acra concepts, use cases, details on cryptographic, and security design.

You might want to:

- Read about using the lightweight [HTTP web server AcraWebConfig](https://github.com/cossacklabs/acra/wiki/AcraWebConfig) we provide to manage AcraServer configuration in a simple fashion.
- Read the notes on [security design](https://github.com/cossacklabs/acra/wiki/Security-design) and [intrusion detection](https://github.com/cossacklabs/acra/wiki/Intrusion-detection) to better understand what you get when using Acra and what is the threat model that Acra operates in. 
- Read [some notes on making Acra stronger / more productive and efficient](https://github.com/cossacklabs/acra/wiki/Tuning-Acra), and on adding security features or increasing throughput, depending on your goals and security model.
- Read about the [logging format](https://github.com/cossacklabs/acra/wiki/Logging) that Acra supports if you are using a SIEM system.

All of our documentation (including with the Acra documentation) can also be found on our dedicated [Cossack Labs Documentation Server](https://docs.cossacklabs.com/products/acra/). However, it is still in an early beta so there might be dragons 🐉.
  
## Project status

This open source version of Acra is free-to-use. Please let us know in the [Issues](https://www.github.com/cossacklabs/acra/issues) if you stumble upon a bug, see a possible enhancement, or have a comment on security design.

There’s [commercial version of Acra](https://www.cossacklabs.com/acra/) available, which provides better performance, redunancy/load balancing, comes pre-configured with cryptoprimitives you want (FIPS, GOST), integrates with key/secret management tools in your stack, and has plenty of goodies for your Ops and SREs to operate Acra conveniently - deployment automation, scaling, monitoring and logging [Talk to us](mailto:sales@cossacklabs.com) if you're interested.

## Contributing to us

If you’d like to contribute your code or other kind of input to Acra, you’re very welcome. Your starting point for contributing should be this [Contribution Wiki page](https://github.com/cossacklabs/acra/wiki/Contributing-to-Acra).


## License

Acra is licensed as Apache 2 open source software.


## Contacts

If you want to ask a technical question, feel free to raise an [issue](https://github.com/cossacklabs/acra/issues) or write to [dev@cossacklabs.com](mailto:dev@cossacklabs.com).

To talk to the business wing of Cossack Labs Limited, drop us an email to [info@cossacklabs.com](mailto:info@cossacklabs.com).
   
[![Blog](https://img.shields.io/badge/blog-cossacklabs.com-7a7c98.svg)](https://cossacklabs.com/) [![Twitter CossackLabs](https://img.shields.io/badge/twitter-cossacklabs-fbb03b.svg)](http://twitter.com/cossacklabs) [![Medium CossackLabs](https://img.shields.io/badge/medium-%40cossacklabs-orange.svg)](https://medium.com/@cossacklabs/)


