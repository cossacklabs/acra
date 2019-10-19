package com.cossacklabs.examples;

import com.cossacklabs.themis.*;
import com.cossacklabs.acrawriter.*;

import java.io.IOException;
import java.util.Base64;

public class Main {

  public static void main(String[] args) {
    try {
      generateAcraStructLocally();
      generateAcraStructWithZoneLocally();

    } catch (SecureCellException | NullArgumentException | InvalidArgumentException | KeyGenerationException | IOException e) {
      e.printStackTrace();
    }
  }

  // Generate storage keys, AcraWriter is using <client_id>_storage.pub public key
  // https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter#client-side-with-zones
  private static void generateAcraStructLocally() throws SecureCellException, NullArgumentException, InvalidArgumentException, KeyGenerationException, IOException {
    String message = "local acrastruct";

    String acraTranslatorPublicKey = "VUVDMgAAAC240mpnAx8FSrZxhVNPsnhhZFYAm0+ARiRDdXPKAW0vI/2AY0QM";
    PublicKey publicKey = new PublicKey(Base64.getDecoder().decode(acraTranslatorPublicKey.getBytes()));

    AcraWriter aw = new AcraWriter();
    AcraStruct acraStruct = aw.createAcraStruct(message.getBytes(), publicKey, null);

    String encodedString = Base64.getEncoder().encodeToString(acraStruct.toByteArray());
    System.out.println("acrastruct in base64 = " + encodedString);
  }

  // Generate Zone keys, AcraWriter is using <zone_id>_zone.pub public key
  // https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter#client-side-with-zones
  private static void generateAcraStructWithZoneLocally() throws SecureCellException, NullArgumentException, InvalidArgumentException {
    String message = "acrastruct with zone";
    String zoneID = "DDDDDDDDbBnbDdyQhsIKDHmg";

    String acraTranslatorZoneKey = "VUVDMgAAAC0a1L6iAj46qMJ7eofpjF2h/+u+uItIvpyvZcNW+5enohvCIY6G";
    PublicKey publicKey = new PublicKey(Base64.getDecoder().decode(acraTranslatorZoneKey.getBytes()));

    try {
      AcraWriter aw = new AcraWriter();
      AcraStruct acraStructWithZone = aw.createAcraStruct(message.getBytes(), publicKey, zoneID.getBytes());

      String encodedString = Base64.getEncoder().encodeToString(acraStructWithZone.toByteArray());
      System.out.println("acrastruct with zone in base64 = " + encodedString);

    } catch (KeyGenerationException | IOException e) {
      e.printStackTrace();
    }
  }
}
