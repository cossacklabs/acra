package com.cossacklabs.acrawriter;

import com.cossacklabs.themis.AsymmetricKey;
import com.cossacklabs.themis.InvalidArgumentException;
import com.cossacklabs.themis.KeyGenerationException;
import com.cossacklabs.themis.Keypair;
import com.cossacklabs.themis.KeypairGenerator;
import com.cossacklabs.themis.NullArgumentException;
import com.cossacklabs.themis.PublicKey;
import com.cossacklabs.themis.SecureCell;
import com.cossacklabs.themis.SecureCellData;
import com.cossacklabs.themis.SecureCellException;
import com.cossacklabs.themis.SecureMessage;
import com.cossacklabs.themis.SecureMessageWrapException;

import org.junit.Test;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;

import static java.lang.System.in;
import static junit.framework.Assert.assertNotNull;
import static junit.framework.Assert.assertTrue;

public class AcraWriterTest {

    @Test
    public void testCreateEmptyAcraStruct() {
        AcraWriter aw = new AcraWriter();
        assertNotNull(aw);

        try {
            AcraStruct a = aw.createAcraStruct(null, null, null);
            AcraStruct b = aw.createAcraStruct("message".getBytes(), null, null);
        } catch (NullArgumentException e) {
            // completely fine
        } catch (KeyGenerationException | InvalidArgumentException | SecureCellException | IOException e) {
            assertTrue("If no message or pubkey, NullArgumentException should be generated", false);
            e.printStackTrace();
        }
    }

    @Test
    public void testCreateAcraStructWithInvalidKey() {
        AcraWriter aw = new AcraWriter();
        assertNotNull(aw);

        try {
            AcraStruct as = aw.createAcraStruct("message".getBytes(), new PublicKey("some pub key".getBytes()), null);
        } catch (InvalidArgumentException e) {
            // completely fine
        } catch (KeyGenerationException | NullArgumentException | SecureCellException | IOException e) {
            assertTrue("If pub key is invalid, InvalidArgumentException should be generated", false);
            e.printStackTrace();
        }
    }

    @Test
    public void testCreateAcraStructWithoutZone() {
        AcraWriter aw = new AcraWriter();
        assertNotNull(aw);

        try {
            Keypair keypair = KeypairGenerator.generateKeypair(AsymmetricKey.KEYTYPE_EC);
            AcraStruct as = aw.createAcraStruct("message".getBytes(), keypair.getPublicKey(), null);
        } catch (InvalidArgumentException | KeyGenerationException | NullArgumentException | SecureCellException | IOException e) {
            assertTrue("Shouldn't be any exceptions", false);
            e.printStackTrace();
        }
    }

    @Test
    public void testCreateAcraStructWithZone() {
        AcraWriter aw = new AcraWriter();
        assertNotNull(aw);

        try {
            Keypair keypair = KeypairGenerator.generateKeypair(AsymmetricKey.KEYTYPE_EC);
            AcraStruct as = aw.createAcraStruct("message".getBytes(), keypair.getPublicKey(), "zone ID".getBytes());
        } catch (InvalidArgumentException | KeyGenerationException | NullArgumentException | SecureCellException | IOException e) {
            assertTrue("Shouldn't be any exceptions", false);
            e.printStackTrace();
        }
    }

    @Test
    public void testCreateAcraStructFormat() {
        AcraWriter aw = new AcraWriter();
        assertNotNull(aw);

        try {
            byte[] zoneID = "some zone id".getBytes();
            byte[] message = "message to encrypt".getBytes();
            Keypair keypair = KeypairGenerator.generateKeypair(AsymmetricKey.KEYTYPE_EC);

            AcraStruct acraStruct = aw.createAcraStruct(message, keypair.getPublicKey(), zoneID);

            byte[] acraStructBytes = acraStruct.toByteArray();
            ByteArrayInputStream stream = new ByteArrayInputStream(acraStructBytes);

            // read header=
            int headerLength = 8;
            byte[] header = new byte[headerLength];
            int i = stream.read(header, 0, headerLength);

            for (byte b : header) {
                assertTrue("Header byte should be 34", b == 34);
            }

            // pub key
            int pubkeyLength = 45;
            byte[] pubKeyBytes = new byte[pubkeyLength];
            i = stream.read(pubKeyBytes, 0, pubkeyLength);
            PublicKey pubKey = new PublicKey(pubKeyBytes);
            assertNotNull("Should be able to read public key", pubKey);

            // encrypted symm key
            int encryptedSymKeyLength = 84;
            byte[] encryptedSymKey = new byte[encryptedSymKeyLength];
            i = stream.read(encryptedSymKey, 0, encryptedSymKeyLength);

            // create decryptor
            SecureMessage sm = new SecureMessage(keypair.getPrivateKey(), pubKey);
            assertNotNull("Should be able to init SecureMessage from read public key", sm);

            byte[] decryptedSymmKey = sm.unwrap(encryptedSymKey);
            assertNotNull("Should be able to decrypt symm key", decryptedSymmKey);
            assertTrue("Decrypted symm key should not be empty", decryptedSymmKey.length > 0);

            // length of encrypted data
            int encryptedDataLengthLength = 8;
            byte[] encryptedDataLength = new byte[encryptedDataLengthLength];
            i = stream.read(encryptedDataLength, 0, encryptedDataLengthLength);

            // convert encrypted data length from little endian
            ByteBuffer bb = ByteBuffer.wrap(encryptedDataLength);
            bb.order(ByteOrder.LITTLE_ENDIAN);

            // technically, encryptedDataLength max size is uint64, which is 2^64-1,
            // but in Java max array length is int, which is 2^32-1
            int encryptedDataLengthI = bb.getInt();

            // encrypted data
            byte[] encryptedData = new byte[encryptedDataLengthI];
            i = stream.read(encryptedData, 0, encryptedDataLengthI);
            assertNotNull("Should be able to read encrypted data", encryptedData);
            assertTrue("Encrypted data should not be empty", encryptedData.length > 0);

            // create decryptor
            SecureCell cell = new SecureCell(decryptedSymmKey);
            byte[] decryptedData = cell.unprotect(zoneID, new SecureCellData(encryptedData, null));
            assertNotNull("Should be able to decrypt encrypted data", decryptedData);
            assertTrue("Decrypted data should not be empty", decryptedData.length > 0);

            assertTrue("Encrypted and decrypted data should be equal", Arrays.equals(decryptedData, message));

            stream.close();

        } catch (InvalidArgumentException | KeyGenerationException | NullArgumentException | SecureCellException | IOException | SecureMessageWrapException e) {
            e.printStackTrace();
            assertTrue("Shouldn't be any exceptions", false);
        }
    }
}