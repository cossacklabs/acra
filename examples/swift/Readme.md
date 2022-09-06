See a verbose explanation of how to prepare environment and use the examples in [https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker/](https://github.com/cossacklabs/acra/wiki/Trying-Acra-with-Docker/). 

This example contains AcraStructs generations that are made locally. AcraWriter can't decrypt AcraStructs, only AcraServer and AcraTranslator can. If you are looking for example with AcraServer/AcraTranslator, please, check out [ObjC docs](https://github.com/cossacklabs/acra/tree/master/examples/objc).
  
Please update AcraStorage Public key to yours:

```swift
let aw = AcraWriter()
let acraStoragePublicKey = "VUVDMgAAAC19EoDCAjPFi89Z/Y4bLX9FAzVonJ+Z1GmxKJQo/DvJY8K8nw9V"
let acraStoragePublicKeyData = Data(base64Encoded: acraStoragePublicKey, options: .ignoreUnknownCharacters)!

do {
    let acraStruct = try aw.createAcraStruct(from: "secret data".data(using: .utf8)!,
                                             publicKey: acraStoragePublicKeyData,
                                             zoneID: nil)
    let acraStructBase64 = acraStruct.data.base64EncodedString(options: .lineLength64Characters)
    print("generated acraStruct ->\n\(acraStructBase64)")
    
} catch let error {
    print("Error occurred while generating AcraStruct \(error)", #function)
    return
}
```