This example contains two parts: simple AcraStructs generation, which can be done locally, and decryption using AcraTranslator via HTTP API. For this purpose, AcraConnector and AcraTranslator should be up and running.

See a verbose explanation of what is AcraTranslator and how to run it in [AcraTranslator docs](https://github.com/cossacklabs/acra/wiki/AcraTranslator). 

 
# Building and running

Please run project from Acra repository. Run `MainActivityAcraStructExample`.

## Dependencies

This example depends on `acrawriter` library, which is installed via maven. We use [`bintray`](https://bintray.com/cossacklabs/maven/acrawriter) to distribute it.

First, update your `build.gradle` file with URL to our maven repository:

```
repositories {
        // whatever you have here, add maven
        maven { url "https://dl.bintray.com/cossacklabs/maven/" }
}
```

Then link acrawriter from `app/build.gradle` file:

```
dependencies {
     // ....
    implementation 'com.cossacklabs.com:acrawriter:1.0.1'
}
```

And that's all! 

Under the hood, AcraWriter depends on Themis, which depends on OpenSSL, but you don't need to install them separately.


# Generating AcraStruct without zone

Please update AcraStrorage Public key to yours:

```java
import com.cossacklabs.acrawriter.AcraStruct;
import com.cossacklabs.acrawriter.AcraWriter;

String message = "hello message";
String acraTranslatorPublicKey = "VUVDMgAAAC240mpnAx8FSrZxhVNPsnhhZFYAm0+ARiRDdXPKAW0vI/2AY0QM";
PublicKey publicKey = new PublicKey(Base64.decode(acraTranslatorPublicKey.getBytes(), Base64.NO_WRAP));

AcraWriter aw = new AcraWriter();
AcraStruct acraStruct = aw.createAcraStruct(message.getBytes(), publicKey, null);
```


# Generating AcraStruct with zone

Please update AcraStrorage Zone Public key to yours:

```java
import com.cossacklabs.acrawriter.AcraStruct;
import com.cossacklabs.acrawriter.AcraWriter;

String message = "zone hello message";
String zoneID = "DDDDDDDDbBnbDdyQhsIKDHmg";

String acraTranslatorZoneKey = "VUVDMgAAAC0a1L6iAj46qMJ7eofpjF2h/+u+uItIvpyvZcNW+5enohvCIY6G";
PublicKey publicKey = new PublicKey(Base64.decode(acraTranslatorZoneKey.getBytes(), Base64.NO_WRAP));

AcraWriter aw = new AcraWriter();
AcraStruct acraStruct = aw.createAcraStruct(message.getBytes(), publicKey, zoneID.getBytes());
```
