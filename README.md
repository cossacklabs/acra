<h3 align="center">
  <a href="https://www.cossacklabs.com"><img src="https://github.com/cossacklabs/acra/wiki/Images/acra_web.jpg" alt="Acra: transparent database encryption server" width="500"></a>
  <br>
  Database protection suite with selective encryption and intrusion detection.
  <br>
</h3>

-----

[![CircleCI](https://circleci.com/gh/cossacklabs/acra/tree/master.svg?style=shield)](https://circleci.com/gh/cossacklabs/acra)
[![Go Report Card](https://goreportcard.com/badge/github.com/cossacklabs/acra)](https://goreportcard.com/report/github.com/cossacklabs/acra)

**[Documentation](https://github.com/cossacklabs/acra/wiki) // [Python sample project](https://github.com/cossacklabs/djangoproject.com) // [Ruby sample project](https://github.com/cossacklabs/rubygems.org) // [Examples](https://github.com/cossacklabs/acra/tree/master/examples)**

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

Acra is still a product on a very early development stage: any security tools require enourmous human efforts for validation of the methods, code, and finding possible infrastructural weaknesses. Although we do run Acra in production in several instances, we're continuously enhancing it as we go to everyone's benefit. And Acra still needs ruthless dissection of all of its properties to ensure that the provided security benefits are not rendered useless through implementation problems or increased complexity.

## Cryptography

Acra relies on our cryptographic library [Themis](https://www.github.com/cossacklabs/themis), which implements high-level cryptosystems based on the best availble [open-source implementations](https://github.com/cossacklabs/themis/wiki/Cryptographic-donors) of the [most reliable ciphers](https://github.com/cossacklabs/themis/wiki/Soter). Acra does not contain any self-made cryptographic primitives or obscure ciphers. Instead, to deliver its unique guarantees, Acra relies on the combination of well-known ciphers and smart key management scheme.

## Availability

* Acra source builds with Go versions 1.2.2, 1.3, 1.3.3, 1.4, 1.4.3, 1.5, 1.5.4, 1.6, 1.6.4, 1.7, 1.7.5, 1.8.
* Acra is known to build on: Debian jessie x86_64, Debian jessie i686, CentOS 7(1611) x86_64, CentOS 6.8 i386.
* Acra currently supports PostgreSQL 9.4+ as the database backend; MongoDB and MariaDB (and other MySQL flavours) coming quite soon. 
* Acra has writer libraries for Ruby, Python, Go, and PHP, but you can easily [generate AcraStruct containers](https://github.com/cossacklabs/acra/wiki/AcraStruct) with [Themis](https://github.com/cossacklabs/themis) for any platform you want. 

## How does Acra work?

<p align="center"><img src="https://github.com/cossacklabs/acra/wiki/Images/simplified_arch.png" alt="Acra: simplified architecture" width="500"></p>

After successfully deploying and integrating Acra into your application, follow the 4 steps below:

* Your app talks to **AcraProxy**, local daemon, via PostgreSQL driver. **AcraProxy** emulates your normal PostgreSQL database, forwards all the requests to **AcraServer** over a secure channel, and expects back plaintext output. Then **AcraProxy** forwards it over the initial PostgreSQL connection to the application. It is connected to **AcraServer** via [Secure Session](https://github.com/cossacklabs/themis/wiki/Secure-Session-cryptosystem), which ensures that all the plaintext goes over a protected channel. It is highly desirable to run **AcraProxy** via a separate user to compartmentalise it from the client-facing code. 
* **AcraServer** is the core entity that provides decryption services for all the encrypted envelopes that come from the database, and then re-packs database answers for the application.
* To write protected data to the database, you can use **AcraWriter library**, which generates AcraStructs and helps you  integrate it as a type into your ORM or database management code. You will need Acra's public key to do that. AcraStructs generated by AcraWriter are not readable by it - only the server has the right keys to decrypt it. 
* You can connect to both **AcraProxy** and the database directly when you don't need encrypted reads/writes. However, increased performance might cost you some design elegance (which is sometimes perfectly fine when it's a conscious decision).

To better understand the architecture and data flow, please refer to [Architecture and data flow](https://github.com/cossacklabs/acra/wiki/Architecture-and-data-flow) section in the official documentation.

The typical workflow looks like this: 
- The app encrypts some data using AcraWriter, generating AcraStruct with AcraServer public key, and updates the database. 
- The app sends SQL request through AcraProxy, which forwards it to AcraServer, AcraServer forwards it to the database. 
- Upon receiving the answer, AcraServer tries to detect encrypted envelopes (AcraStructs). If it succeeds, AcraServer decrypts payload and replaces them with plaintext answer, which is then returned to AcraProxy over a secure channel. 
- AcraProxy then provides an answer to the application, as if no complex security instrumentation was ever present within the system.

## 4 steps to start

* Read the Wiki page on [building and installing](https://github.com/cossacklabs/acra/wiki/Quick-start-guide) all the components. Soon they'll be available as pre-built binaries, but for the time being you'll need to fire a few commands to get the binaries going. 
* [Deploy AcraServer](https://github.com/cossacklabs/acra/wiki/Quick-start-guide) binaries in a separate virtual machine (or [try it in a docker container](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker)). Generate keys, put AcraServer public key into both clients (AcraProxy and AcraWriter, see next).
* Deploy [AcraProxy](https://github.com/cossacklabs/acra/wiki/AcraProxy-and-AcraWriter#acraproxy) on each server where you need to read sensitive data. Generate proxy keys, provide a public key to AcraServer. Point your database access code to AcraProxy, access it as your normal database installation.
* Integrate [AcraWriter](https://github.com/cossacklabs/acra/wiki/AcraProxy-and-AcraWriter#acrawriter) into your code where you need to store sensitive data, supply AcraWriter with proper server key.

## Additionally

We fill [wiki](https://github.com/cossacklabs/acra/wiki) with useful articles on the core Acra concepts, use cases, details on cryptographic and security design. You might want to:
- Read notes on [security design](https://github.com/cossacklabs/acra/wiki/Security-design) to better understand what you get with using Acra and what is the threat model Acra operates in. 
- Read [some notes on making Acra stronger / more productive and efficient](https://github.com/cossacklabs/acra/wiki/Tuning-Acra), and on adding security features or increasing throughput, depending on your goals and security model.

## Project status

This open source version of Acra is an early alpha. We're slowly unifying and moving features from its previous incarnation into a community-friendly edition. Please let us know in the [Issues](https://www.github.com/cossacklabs/acra/issues) whenever you stumble upon a bug, see a possible enhancement or have a comment on security design.

## License

Acra is licensed as Apache 2 open source software.

