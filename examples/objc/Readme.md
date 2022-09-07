See a verbose explanation of how to prepare environment and use the examples in [https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker/](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker/). 

This example contains two parts: simple AcraStructs generation, which can be done locally, and decryption using AcraTranslator via HTTP API. For this purpose, AcraConnector and AcraTranslator should be up and running.
  
Please update AcraStrorage Public key to yours:

```objc
AcraWriter * aw = [AcraWriter new];
NSString * acraStoragePublicKey = @"VUVDMgAAAC19EoDCAjPFi89Z/Y4bLX9FAzVonJ+Z1GmxKJQo/DvJY8K8nw9V";
NSData * acraStoragePublicKeyData = [[NSData alloc] initWithBase64EncodedString:acraStoragePublicKey
                                                                      options:NSDataBase64DecodingIgnoreUnknownCharacters];

NSError * generationError;
AcraStruct * acraStruct = [aw createAcraStructFrom:[@"secret message" dataUsingEncoding:NSUTF8StringEncoding]
                                       publicKey:acraStoragePublicKeyData
                                          additionalContext:nil
                                           error:&generationError];
```