<h3 align="center">
  <a href="https://www.cossacklabs.com"><img src="https://github.com/cossacklabs/acra/wiki/Images/acralogo.png" alt="Acra: database security suite" width="500"></a>
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
  <a href="https://github.com/cossacklabs/acra/releases/latest"><img src="https://img.shields.io/badge/Client%20Platforms-Go%20%7C%20Ruby%20%7C%20Python%20%7C%20PHP%20%7C%20NodeJS%20%7C%20iOS-green.svg" alt="Client platforms"></a>
</p>
<br>


| [Documentation](https://github.com/cossacklabs/acra/wiki) | [Acra Live Demo](https://www.cossacklabs.com/acra/#acralivedemo) | [Python sample project](https://github.com/cossacklabs/djangoproject.com) | [Ruby sample project](https://github.com/cossacklabs/rubygems.org) | [Examples](https://github.com/cossacklabs/acra/tree/master/examples) |
| ---- | ---- | ---- | --- | --- |

## What is Acra
Acra - database encryption proxy for data-driven apps.
Acra brings encryption and data leakage prevention to distributed applications, web and mobile apps with database backends. Acra provides selective encryption, multi-layered access control, database leakage prevention and intrusion detection capabilities in a convenient, developer-friendly package.

Acra gives you tools for encrypting the data on the application's side into special [cryptographic containers](https://github.com/cossacklabs/acra/wiki/AcraStruct), storing them in the database or file storage, and then decrypting them in a secure compartmented area (separate virtual machine/container). 

Cryptographic design ensures that no secret (password, key, etc.) leaked from the application or database will be sufficient for decryption of the protected data chunks that originate from it. 

Acra was built with specific user experiences in mind: 

- **quick and easy integration** of security instrumentation;
- **easy to try**: you can experience the full might of Acra without committing to its installation using [Docker containers](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker);
- **compatible with encryption-demanding compliances**: Acra can run on certified crypto-libraries (FIPS, GOST);
- **cryptographic protection of data**: to compromise an Acra-powered app, an attacker will need to compromise a separate compartmented server, AcraServer - or more specifically - its key storage and database; until AcraServer is compromised, the data is safe.
- **cryptography is hidden under the hood**: you're safe from the risk of selecting the wrong key length or algorithm padding;
- **secure default settings** to get you going; 
- **intrusion detection** to give you an early warning if something wrong is going on;
- **SQL injections prevention** through a built-in SQL firewall;
- **ops-friendly**: Acra can be easy configured and automated using a configuration automation environment.


Acra is a continuously developing security tool. And as any proper security tool, it requires enormous human efforts for validation of the methods, code, and finding possible infrastructural weaknesses. We're constantly enhancing and improving Acra as we go. This is done to ensure that the provided security benefits are not rendered useless through implementation problems or increased complexity.

## Cryptography

Acra relies on our cryptographic library [Themis](https://www.github.com/cossacklabs/themis), which implements high-level cryptosystems based on the best available [open-source implementations](https://github.com/cossacklabs/themis/wiki/Cryptographic-donors) of the [most reliable ciphers](https://github.com/cossacklabs/themis/wiki/Soter). Acra does not contain any self-made cryptographic primitives or obscure ciphers. To deliver its unique guarantees, Acra relies on the combination of well-known ciphers and a smart key management scheme.

The [enterprise version of Acra](https://www.cossacklabs.com/acra/) can run on the certified crypto-libraries of your choice (i.e. FIPS, GOST), [drop us an email](mailto:sales@cossacklabs.com) to get a quote.

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

## Acra Live Demo

| 💻 [Request a free Acra Live Demo](https://www.cossacklabs.com/acra/#acralivedemo) 💻 |
|--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|

## How does Acra work?

To better understand the architecture and data flow, please refer to [Architecture and data flow](https://github.com/cossacklabs/acra/wiki/Architecture-and-data-flow) section in the GitHub documentation. Or refer to the documentation on the official Cossack Labs documentation server to get the most recent version of the [documentation and tutorials for Acra](https://docs.cossacklabs.com/products/acra/).

### Protecting data in SQL databases with AcraWriter and AcraServer

<p align="center"><img src="https://raw.githubusercontent.com/wiki/cossacklabs/acra/Images/readme/AcraArchi-Readme.png" alt="Acra Server: simplified architecture" width="500"></p>

This is what the process of encryption and decryption data in a database looks like:

- Your application encrypts some data through [**AcraWriter**](https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter), generating an [**AcraStruct**](https://github.com/cossacklabs/acra/wiki/AcraStruct) using Acra storage public key and updates the database. AcraStructs generated by AcraWriter can't be decrypted by it — only the Acra's server side has the right keys for decryption.
- To retrieve the decrypted data, your application talks to [**AcraServer**](https://github.com/cossacklabs/acra/wiki/How-AcraServer-works). It is a server-side service that works as database proxy: it sits transparently between your application and the database, listens silently to all the traffic that's coming to and from the database. 
- AcraServer monitors the incoming SQL requests and blocks the unwanted ones using the built-in configurable firewall called [**AcraCensor**](https://github.com/cossacklabs/acra/wiki/acracensor). AcraServer only sends allowed requests to the database. Certain configurations for AcraServer can be adjusted remotely using [**AcraWebConfig**](https://github.com/cossacklabs/acra/wiki/AcraWebConfig) web server.
- Upon receiving the database response, AcraServer tries to detect the AcraStructs, decrypts them and returns the decrypted data to the application.
-[**AcraConnector**](https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter) is a client-side daemon responsible for providing encrypted and authenticated connection between the application and AcraServer. AcraConnector runs under a separate user / in a separate container and acts as a middleware. It accepts connections from the application, extra transport encryption layer using TLS or [Themis Secure Session](https://github.com/cossacklabs/themis/wiki/Secure-Session-cryptosystem), sends the data to AcraServer, receives the result and sends it back to the application.

### Protecting data in any file storage with AcraWriter and AcraTranslator

<p align="center"><img src="https://raw.githubusercontent.com/wiki/cossacklabs/acra/Images/readme/AcraArchi-AT-Readme.png" alt="Acra Translator: simplified architecture" width="500"></p>

In some use cases, the application can store encrypted data as separate blobs (files that are not in a database - i.e. in the S3 bucket, local file storage, etc.). In this case, you can use [**AcraTranslator**](https://github.com/cossacklabs/acra/wiki/AcraTranslator) - a lightweight server that receives [**AcraStructs**](https://github.com/cossacklabs/acra/wiki/AcraStruct) and returns the decrypted data.

This is what the process of encryption and decryption data using AcraTranslator looks like:

- Your application encrypts some data using [**AcraWriter**](https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter), generating an AcraStruct using Acra storage public key and puts the data into any file storage. AcraStructs generated by AcraWriter can't be decrypted by it — only the Acra's server side has the right keys for decrypting it.
- To decrypt an AcraStruct, your application sends it to [**AcraTranslator**](https://github.com/cossacklabs/acra/wiki/AcraTranslator) as a binary blob via HTTP or gRPC API. AcraTranslator doesn’t care about the source of the data, it is responsible for holding all the secrets required for data decryption and for actually decrypting the data.
- AcraTranslator decrypts AcraStructs and returns the decrypted data to the application.
- To avoid sending the plaintext via an unsecured channel, AcraTranslator requires the use of [**AcraConnector**](https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter), a client-side daemon responsible for providing encrypted and authenticated connection between the application and AcraServer. AcraConnector runs under a separate user / in a separate container and acts as a middleware. It accepts connections from the application, adds transport encryption layer using TLS or [Themis Secure Session](https://github.com/cossacklabs/themis/wiki/Secure-Session-cryptosystem), sends data to AcraServer, receives the result, and sends it back to the application.

AcraTranslator and AcraServer are fully independent server-side components and can be used together or separately depending on your infrastructure.

## Demo stand

For a quick and easy start, we recommend [trying Acra with Docker](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker) first. Using only two commands, you will get all the Acra's components and database up and running, with a secure transport layer between them. We prepared several typical infrastructure variants to experiment with.

* Select one appropriate use case from the [pre-made configurations](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker#compose-files): use AcraServer-based configuration to protect data in a database or select AcraTranslator to protect files or any binary blobs stored anywhere. 
* Launch Acra's server-side by running the selected docker-compose file: it will generate the appropriate keys, put them into correct folders, perform a public key exchange, run selected services and database, and then it will listen to incoming connections.
* Integrate [AcraWriter](https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter#acrawriter) into your application code where you need to protect sensitive data, supply AcraWriter with an Acra storage public key (generated by docker-compose on the previous step). Encrypt data into AcraStructs and send them into the database or file storage.
* Decrypt data by reading the database through AcraServer or by decrypting the files through AcraTranslator.

Please use the docker-demo stand for testing/experimenting purposes only as encryption keys are pre-generated in the configuration.

## Manual launch

For production environments, we insist on generating and exchanging keys manually. Refer to the [Quick Start guide](https://github.com/cossacklabs/acra/wiki/Quick-start-guide#installing-acra-from-the-cossack-labs-repository) to understand how to download and launch Acra components, generate keys, and perform a key exchange properly.


## Additionally

For the versions of Acra up to the version 0.82.0, the documentation was mostly maintained and updated in the [GitHub Wiki documentation for Acra](https://github.com/cossacklabs/acra/wiki) with useful articles about the core Acra concepts, use cases, details on cryptographic, and security design. Starting with the version 0.82.0, we stop updating the GitHub Wiki documentation. The basic principles still hold true, but for the most recent versions of the docs, tutorials, and demos, please visit the official [Cossack Labs documentation server](https://docs.cossacklabs.com/products/acra/). However, it is still partially in beta so there might be dragons 🐉. Please report any bugs or submit suggestions about making the documentation better to info@cossacklabs.com.


To gain an initial understanding of Acra, you might want to:

- Read about using the lightweight [HTTP web server AcraWebConfig](https://docs.cossacklabs.com/pages/documentation-acra/#acrawebconfig) we provide to manage AcraServer configuration in a simple fashion.
- Read the notes on [security design](https://docs.cossacklabs.com/pages/security-design/) and [intrusion detection](https://docs.cossacklabs.com/pages/intrusion-detection/) to better understand what you get when using Acra and what is the threat model that Acra operates in. 
- Read [some notes on making Acra stronger / more productive and efficient](https://docs.cossacklabs.com/pages/tuning-acra/), and on adding security features or increasing throughput, depending on your goals and security model.
- Read about the [logging format](https://docs.cossacklabs.com/pages/documentation-acra/#logging-in-acra) that Acra supports if you are using a SIEM system.


## GDPR and HIPAA

Acra can help you comply with GDPR and HIPAA regulations. Configuring and using Acra in a designated form will cover most demands described in articles 25, 32, 33 and 34 of GDPR, and PII data protection demands from HIPAA. Read more about [Acra and compliance](https://github.com/cossacklabs/acra/wiki/Acra-and-GDPR-compliance).

## Open source vs Enterprise

This open source version of Acra is free to use. Please let us know in the [Issues](https://www.github.com/cossacklabs/acra/issues) if you stumble upon a bug, see a possible enhancement, or have a comment on security design.

There’s a [commercial version of Acra](https://www.cossacklabs.com/acra/) available. It provides better performance, redunancy/load balancing, comes pre-configured with crypto-primitives of your choice (FIPS, GOST), integrates with key/secret management tools in your stack, and has plenty of goodies for your Ops and SREs to operate Acra conveniently - deployment automation, scaling, monitoring, and logging. [Talk to us](mailto:sales@cossacklabs.com) if you're interested.

## Security consulting

It takes more than just getting cryptographic code to compile to secure the sensitive data. Acra won't make you “compliant out of the box” and no other tool will. 

[We help companies](https://www.cossacklabs.com/dgap/) to plan their data security strategy by auditing, assessing data flow, and classifying the data, enumerating the risks. We do the hardest, least-attended part of compliance – turning it from the “cost of doing business” into the “security framework that prevents risks”.


## Contributing to us

If you’d like to contribute your code or provide any other kind of input to Acra, you’re very welcome. Your starting point for contributing should be this [Contribution Wiki page](https://github.com/cossacklabs/acra/wiki/Contributing-to-Acra).


## License

Acra is licensed as Apache 2 open source software.


## Contacts

If you want to ask a technical question, feel free to raise an [issue](https://github.com/cossacklabs/acra/issues) or write to [dev@cossacklabs.com](mailto:dev@cossacklabs.com).

To talk to the business wing of Cossack Labs Limited, drop us an email to [info@cossacklabs.com](mailto:info@cossacklabs.com).
   
[![Blog](https://img.shields.io/badge/blog-cossacklabs.com-7a7c98.svg)](https://cossacklabs.com/) [![Twitter CossackLabs](https://img.shields.io/badge/twitter-cossacklabs-fbb03b.svg)](http://twitter.com/cossacklabs) [![Medium CossackLabs](https://img.shields.io/badge/medium-%40cossacklabs-orange.svg)](https://medium.com/@cossacklabs/)


