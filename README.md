<h3 align="center">
  <a href="https://www.cossacklabs.com"><img src="https://github.com/cossacklabs/acra/wiki/Images/acra_web.jpg" alt="Acra: transparent database encryption server" width="500"></a>
  <br>
  Database protection suite with selective encryption and intrusion detection.
  <br>
</h3>

-----

<p align="center">
  <a href="https://github.com/cossacklabs/ara/releases/latest"><img src="https://img.shields.io/github/release/cossacklabs/acra.svg" alt="GitHub release"></a>
  <a href="https://circleci.com/gh/cossacklabs/acra"><img src="https://circleci.com/gh/cossacklabs/acra/tree/master.svg?style=shield" alt="Circle CI"></a>
  <a href='https://coveralls.io/github/cossacklabs/themis'><img src='https://coveralls.io/repos/github/cossacklabs/themis/badge.svg?branch=master' alt='Coverage Status' /></a>
  <a href='https://goreportcard.com/report/github.com/cossacklabs/acra'><img class="badge" tag="github.com/cossacklabs/acra" src="https://goreportcard.com/badge/github.com/cossacklabs/acra"></a>
  <br/><a href="https://github.com/cossacklabs/themis/releases/latest"><img src="https://img.shields.io/badge/Server%20Platforms-Ubuntu%20%7C%20Debian%20%7C%20CentOS-green.svg" alt="Server platforms"></a>
  <a href="https://github.com/cossacklabs/themis/releases/latest"><img src="https://img.shields.io/badge/Client%20Platforms-Go%20%7C%20Ruby%20%7C%20Python%20%7C%20PHP%20%7C%20NodeJS-green.svg" alt="Client platforms"></a>
</p>
<br>


|[Documentation](https://github.com/cossacklabs/acra/wiki) | [Python sample project](https://github.com/cossacklabs/djangoproject.com) | [Ruby sample project](https://github.com/cossacklabs/rubygems.org) | [Examples](https://github.com/cossacklabs/acra/tree/master/examples) |
| ---- | ---- | ---- | --- |

## What is Acra

Acra helps you easily secure your databases in distributed, microservice-rich environments. It allows you to selectively encrypt sensitive records with [strong multi-layer cryptography](https://github.com/cossacklabs/acra/wiki/AcraStruct), detect potential intrusions and SQL injections and cryptographically compartmentalize data stored in large sharded schemes. Acra's security model guarantees that if your database or your application become compromised, they will not leak sensitive data, or keys to decrypt them. 

Acra gives you means to encrypt the data on the application's side into a special cryptographic container, and store it in the database and then decrypt in secure compartmented area (separate virtual machine/container). Cryptographic design ensures that no secret (password, key, anything) leaked from the application or database is sufficient for decryption of the protected data chunks that originate from it. 

Acra was built with specific user experiences in mind: 

- **quick and easy integration** of security instrumentation.
- **cryptographic protection** of data in the threat model where **all other parts of the infrastructure could be compromised**, and if AcraServer isn't compromised, the data is safe. 
- **proper abstraction** of all cryptographic processes: you're safe from the risk of choosing the wrong key length or algorithm padding. 
- **strong default settings** to get you going. 
- **intrusion detection** to let you know early that something wrong is going on.
- **high degree of configurability** to create perfect balance between the extra security features and performance. 
- **automation-friendly**: most of Acra's features were built to be easily configured / automated from configuration automation environment.
- **limited attack surface**: to compromise Acra-powered app, an attacker will need to compromise the separate compartmented server, AcraServer - more specifically - it's key storage, and the database. 

Acra is still a product in a early development stage. And any security tools require enourmous human efforts for validation of the methods, code, and finding possible infrastructural weaknesses. Although we do run Acra in production in several instances, we're continuously enhancing and improving it as we go. And Acra still needs ruthless dissection of all of its properties to ensure that the provided security benefits are not rendered useless through implementation problems or increased complexity.

## Cryptography

Acra relies on our cryptographic library [Themis](https://www.github.com/cossacklabs/themis), which implements high-level cryptosystems based on the best availble [open-source implementations](https://github.com/cossacklabs/themis/wiki/Cryptographic-donors) of the [most reliable ciphers](https://github.com/cossacklabs/themis/wiki/Soter). Acra does not contain any self-made cryptographic primitives or obscure ciphers. Instead, to deliver its unique guarantees, Acra relies on the combination of well-known ciphers and smart key management scheme.

## Availability

* Acra source builds and tests with Go versions 1.7 – 1.10.
* Acra is known to build on: 

| Distributive        | Go versions                     |
|---------------------|---------------------------------|
| CentOS              | 1.8.3 (system)                  |
| Debian Stretch      | 1.7.4 (system)                  |
| Debian Jessie       | latest (1.3.3 is not supported) |
| Ubuntu Artful       | 1.8.3 (system)                  |
| Ubuntu Trusty       | latest (1.2.1 is not supported) |
| Ubuntu Xenial Xerus | latest |
| i386/Debian Stretch | 1.7.4 (system)                  |
| i386/Debian Jessie  | latest (1.3.3 is not supported) |
| i386/Ubuntu Artful  | 1.8.3 (system)                  |
| i386/Ubuntu Trusty  | latest (1.2.1 is not supported) |

* Acra currently supports PostgreSQL 9.4+ as the database backend. 
* Starting with Acra [`0.77.0`](https://github.com/cossacklabs/acra/releases/tag/0.77.0), we have integrated Acra with MySQL 5.7+ database, but it is still a fresh feature, which we are extensively testing to ensure its full support. Please report any MySQL bugs you may encounter through [Issues](https://github.com/cossacklabs/acra/issues). MongoDB support is coming soon, too. 
* Acra has [writer libraries](https://github.com/cossacklabs/acra/wiki/Acrawriter-installation) for Ruby, Python, Go, and PHP, but you can easily [generate AcraStruct containers](https://github.com/cossacklabs/acra/wiki/AcraStruct) with [Themis](https://github.com/cossacklabs/themis) for any platform you want. 

## How does Acra work?

<p align="center"><img src="https://github.com/cossacklabs/acra/wiki/Images/simplified_arch.png" alt="Acra: simplified architecture" width="500"></p>

After successfully deploying and integrating Acra into your application, follow the 4 steps below:

* Your app talks to **AcraConnector**, local daemon, via PostgreSQL/MySQL driver. **AcraConnector** emulates your normal PostgreSQL/MySQL database, forwards all the requests to **AcraServer** over a secure channel, and expects a plaintext output back.
* Then **AcraConnector** forwards it over the initial database connection to the application. It is connected to **AcraServer** via [Secure Session](https://github.com/cossacklabs/themis/wiki/Secure-Session-cryptosystem) or TLS, which ensures that the plaintext goes over a protected channel. It is highly desirable to run **AcraConnector** via a separate user to compartmentalise it from the client-facing code.
* **AcraServer** is the core entity that provides decryption services for all the encrypted envelopes that come from the database, and then re-packs database answers for the application. **AcraCensor** is part of AcraServer that allows customising the firewall rules for all the requests coming to the MySQL database.
* To write the protected data to the database, you can use **AcraWriter library**, which generates AcraStructs and helps you  integrate it as a type into your ORM or database management code. You will need Acra's public key to do that. AcraStructs generated by AcraWriter are not readable by it — only the server has the right keys to decrypt it. 
* You can connect to both **AcraConnector** and the database directly when you don't need encrypted reads/writes. However, increased performance might cost you some design elegance (which is sometimes perfectly fine when it's a conscious decision).

To better understand the architecture and data flow, please refer to [Architecture and data flow](https://github.com/cossacklabs/acra/wiki/Architecture-and-data-flow) section in the official documentation.

The typical workflow looks like this: 

- The app encrypts some data using AcraWriter, generating AcraStruct with AcraServer public key, and updates the database. 
- The app sends SQL request through AcraConnector, which forwards it to AcraServer.
- AcraServer passes each query through AcraCensor, which can be configured to blacklist or whitelist some queries. AcraServer forwards the allowed queries to the database. AcraCensor can currently be only enabled for MySQL databases.
- Upon receiving the answer, AcraServer tries to detect encrypted envelopes (AcraStructs). If it succeeds, AcraServer decrypts payload and replaces them with plaintext answer, which is then returned to AcraConnector over a secure channel.
- AcraConnector then provides an answer to the application, as if no complex security instrumentation was ever present within the system.

## 4 steps to start

* Read the [Quick start guide](https://github.com/cossacklabs/acra/wiki/Quick-start-guide) to launch all the components. We provide different ways of installing Acra: using Docker, downloading binaries, building from source. 
* [Deploy AcraServer](https://github.com/cossacklabs/acra/wiki/Quick-start-guide) binaries in a separate virtual machine (or [try it in a docker container](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker)). [Generate keys](https://github.com/cossacklabs/acra/wiki/Key-Management), put AcraServer public key into both clients (AcraConnector and AcraWriter, see next).
* Deploy [AcraConnector](https://github.com/cossacklabs/acra/wiki/AcraProxy-and-AcraWriter#acraproxy) on each server where you need to read sensitive data. Generate acra-connector keys, provide a public key to AcraServer. Point your database access code to AcraConnector, access it as your normal database installation.
* Integrate [AcraWriter](https://github.com/cossacklabs/acra/wiki/AcraProxy-and-AcraWriter#acrawriter) into your code where you need to store sensitive data, supply AcraWriter with proper server key.

## Additionally

We fill the [Wiki documentation](https://github.com/cossacklabs/acra/wiki) with useful articles about the core Acra concepts, use cases, details on cryptographic and security design. 

You might want to:

- Read about using the lightweight [HTTP web server AcraWebConfig](https://github.com/cossacklabs/acra/wiki/AcraWebConfig) we provide to manage AcraServer configuration in a simple fashion.
- Read the notes on [security design](https://github.com/cossacklabs/acra/wiki/Security-design) and [intrusion detection](https://github.com/cossacklabs/acra/wiki/Intrusion-detection) to better understand what you get when using Acra and what is the threat model that Acra operates in. 
- Read [some notes on making Acra stronger / more productive and efficient](https://github.com/cossacklabs/acra/wiki/Tuning-Acra), and on adding security features or increasing throughput, depending on your goals and security model.
- Read about the [logging format](https://github.com/cossacklabs/acra/wiki/Logging) that Acra supports if you are using any SIEM system.  
## Project status

This open source version of Acra is an early beta. We're slowly unifying and moving features from its previous incarnation into a community-friendly edition. Please let us know in the [Issues](https://www.github.com/cossacklabs/acra/issues) whenever you stumble upon a bug, see a possible enhancement, or have a comment on security design.

## Contributing to us
If you’d like to contribute your code or other kind of input to Acra, you’re very welcome. Your starting point for contributing should be this [Contribution Wiki page](https://github.com/cossacklabs/acra/wiki/Contributing-to-Acra).


## License

Acra is licensed as Apache 2 open source software.


## Contacts

If you want to ask a technical question, feel free to raise an [issue](https://github.com/cossacklabs/acra/issues) or write to [dev@cossacklabs.com](mailto:dev@cossacklabs.com).

To talk to the business wing of Cossack Labs Limited, drop us an email to [info@cossacklabs.com](mailto:info@cossacklabs.com).
   
[![Blog](https://img.shields.io/badge/blog-cossacklabs.com-7a7c98.svg)](https://cossacklabs.com/) [![Twitter CossackLabs](https://img.shields.io/badge/twitter-cossacklabs-fbb03b.svg)](http://twitter.com/cossacklabs) [![Medium CossackLabs](https://img.shields.io/badge/medium-%40cossacklabs-orange.svg)](https://medium.com/@cossacklabs/)


