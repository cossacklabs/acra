This example contains two parts: simple AcraStructs generation, which can be done locally, and decryption using AcraTranslator via HTTP API. For this purpose, AcraConnector and AcraTranslator should be up and running.

See a verbose explanation of what is AcraTranslator and how to run it in [AcraTranslator docs](https://github.com/cossacklabs/acra/wiki/AcraTranslator). 

 
# Building and running

Please run project from Acra repository. Run `MainActivityAcraStructExample`.

## Dependencies

1. AcraWriter and AcraStruct files are placed in the [`acra/wrappers/java`](https://github.com/cossacklabs/acra/tree/master/wrappers/java/com/cossacklabs/acrawriter) folder. Grab files into your project!

2. AcraWriter depends on Themis. This project has included Themis as Android `.aar` library: `app/libs/themis-release.aar`, linked by gradle (inside `app/build.gradle`).


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

# Re-building Themis library

1. Download Themis repository https://github.com/cossacklabs/themis

2. Compile BoringSSL for android architectures, check instructions in the [themis -> Building and Installing -> Android](https://github.com/cossacklabs/themis/wiki/Building-and-installing#android) section. 

3. Build `themis.aar` archive:
https://github.com/cossacklabs/themis/wiki/Building-and-installing#android

  You will get it in the themis folder `build/outputs/aar/`. Copy archive into `acra/examples/android_java/AcraWriterAndroidApp/app/libs/` folder and rename to `themis-release.aar`

4. Now you can run this example :)

