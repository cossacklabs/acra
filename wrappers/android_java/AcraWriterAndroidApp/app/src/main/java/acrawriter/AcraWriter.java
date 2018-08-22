package acrawriter;

import com.cossacklabs.themis.AsymmetricKey;
import com.cossacklabs.themis.InvalidArgumentException;
import com.cossacklabs.themis.KeyGenerationException;
import com.cossacklabs.themis.Keypair;
import com.cossacklabs.themis.KeypairGenerator;
import com.cossacklabs.themis.NullArgumentException;
import com.cossacklabs.themis.PrivateKey;
import com.cossacklabs.themis.PublicKey;
import com.cossacklabs.themis.SecureCell;
import com.cossacklabs.themis.SecureCellData;
import com.cossacklabs.themis.SecureCellException;
import com.cossacklabs.themis.SecureMessage;
import com.cossacklabs.themis.SecureMessageWrapException;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;

/**
 * AcraWriter generates AcraStructs, specially encrypted data, from provided plaintext.
 * AcraStruct encrypts data using mix of symmetric and asymmetric encryption,
 * using Themis Secure Cell and Themis Secure Message. Data is encrypted with publicKey,
 * that represents AcraStorage public key (known as <client_id>_storage.pub) or
 * with AcraZonePublicKeys (known as <zone_id>_zone.pub).
 *
 * What is AcraWriter and how it works https://github.com/cossacklabs/acra/wiki/AcraConnector-and-AcraWriter
 * What is Zone https://github.com/cossacklabs/acra/wiki/Zones
 */
public class AcraWriter {

    private static byte kSymmetricKeySize = 32;
    private static byte kAcraStructHeaderByte = 34;

    /**
     * @discussion Method to generate AcraStruct from plain text message. Two option are possible: without Zones or with Zones.
     * Without zones: `publicKey` is AcraStorage public key.
     * With zones: `zoneID` is required, `publicKey` is Zone public key.
     * @param message plaintext data to encrypt into AcraStruct.
     * @param peerPublicKey either storage key or zone key, depending if client wants to use Zones.
     * @param zoneID is optional, when client is using Zones. If zoneId is represented as string Id, expected input is [@"some zone id here" dataUsingEncoding:NSUTF8StringEncoding]
     * @return data encrypted into AcraStruct format, or null on error
     */
    public AcraStruct createAcraStruct(byte[] message, PublicKey peerPublicKey, byte[] zoneID) throws NullArgumentException, KeyGenerationException, InvalidArgumentException, SecureCellException, IOException {
        if (message == null || message.length == 0) {
            throw new NullArgumentException("Message to encrypt is empty or not provided");
        }

        if (peerPublicKey == null || peerPublicKey.toByteArray().length == 0) {
            throw new NullArgumentException("Peer public key is not provided");
        }

        // 1. generate EC keypair
        Keypair throwAwayKeypair = KeypairGenerator.generateKeypair(AsymmetricKey.KEYTYPE_EC);

        // 2. generate random symm key with @(kSymmetricKeySize) size
        byte[] randomSymmetricKey = new byte[kSymmetricKeySize];
        new SecureRandom().nextBytes(randomSymmetricKey);

        // 3. encrypt random symmetric key using asymmetric encryption with random private key and acra/zone public key
        PrivateKey privateKey = throwAwayKeypair.getPrivateKey();
        SecureMessage sm = new SecureMessage(privateKey, peerPublicKey);
        byte[] wrappedSymmetricKey;
        try {
            wrappedSymmetricKey = sm.wrap(randomSymmetricKey);
        } catch (SecureMessageWrapException e) {
            throw new InvalidArgumentException("Can't encrypt symmetric key: check if PublicKey is valid");
        }

        // zeroing private key
        // how to zero private key if `toByteArray` returns clone?

        // 4. encrypt payload using symmetric encryption and random symm key
        SecureCell sc = new SecureCell(randomSymmetricKey, SecureCell.MODE_SEAL);
        SecureCellData encryptedPayload = sc.protect(zoneID, message);
        byte[] encryptedData = encryptedPayload.getProtectedData();

        // convert encrypted data length to little endian
        ByteBuffer bb = ByteBuffer.allocate(8); // 8 bytes, uint64
        bb.order(ByteOrder.LITTLE_ENDIAN);
        bb.putInt(encryptedData.length);
        byte[] encryptedDataLengthArray = bb.array();

        // zeroing symm key
        Arrays.fill(randomSymmetricKey, (byte)0);

        // 5. pack acrastruct
        byte[] header = new byte[]{kAcraStructHeaderByte, kAcraStructHeaderByte, kAcraStructHeaderByte, kAcraStructHeaderByte, kAcraStructHeaderByte, kAcraStructHeaderByte, kAcraStructHeaderByte, kAcraStructHeaderByte};
        ByteArrayOutputStream output = new ByteArrayOutputStream();

        try {
            output.write(header);
            output.write(throwAwayKeypair.getPublicKey().toByteArray());
            output.write(wrappedSymmetricKey);
            output.write(encryptedDataLengthArray);
            output.write(encryptedData);

            return new AcraStruct(output.toByteArray());

        } catch (IOException e) {

            throw new IOException("Can't wrap bytes into AcraStruct");
        }
    }
}