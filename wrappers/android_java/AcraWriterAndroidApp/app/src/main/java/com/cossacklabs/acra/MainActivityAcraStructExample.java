package com.cossacklabs.acra;

import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;

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

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.UnsupportedEncodingException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;

public class MainActivityAcraStructExample extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        // Secure cell
        try {
            generateAndSendAcraStruct();
            generateAndSendAcraStructWithZone();

        } catch (InvalidArgumentException | NullArgumentException | SecureCellException e) {
            e.printStackTrace();
        }
    }

    void generateAndSendAcraStruct() throws SecureCellException, NullArgumentException, InvalidArgumentException {
        String acraTranslatorPublicKey = "VUVDMgAAAC240mpnAx8FSrZxhVNPsnhhZFYAm0+ARiRDdXPKAW0vI/2AY0QM";
        String message = "hello message";
        String URL = "http://10.0.2.2:9494/v1/decrypt";

        PublicKey publicKey = new PublicKey(Base64.decode(acraTranslatorPublicKey.getBytes(), Base64.NO_WRAP));

        try {
            byte[] acraStruct = CreateAcraStruct(message.getBytes(), publicKey, null);

            AsyncHttpPost asyncHttpPost = new AsyncHttpPost(acraStruct);
            asyncHttpPost.execute(URL);

        } catch (KeyGenerationException | SecureMessageWrapException | IOException e) {
            e.printStackTrace();
        }
    }

    void generateAndSendAcraStructWithZone() throws SecureCellException, NullArgumentException, InvalidArgumentException {
        String message = "zone hello message";

        String zoneID = "DDDDDDDDbBnbDdyQhsIKDHmg";
        String URL = "http://10.0.2.2:9494/v1/decrypt?zone_id=" + zoneID;

        String acraTranslatorZoneKey = "VUVDMgAAAC0a1L6iAj46qMJ7eofpjF2h/+u+uItIvpyvZcNW+5enohvCIY6G";

        PublicKey publicKey = new PublicKey(Base64.decode(acraTranslatorZoneKey.getBytes(), Base64.NO_WRAP));

        try {
            byte[] acraStruct = CreateAcraStruct(message.getBytes(), publicKey, zoneID.getBytes());

            AsyncHttpPost asyncHttpPost = new AsyncHttpPost(acraStruct);
            asyncHttpPost.execute(URL);

        } catch (KeyGenerationException | SecureMessageWrapException | IOException e) {
            e.printStackTrace();
        }
    }

    static byte kSymmetricKeySize = 32;
    static byte kAcraStructHeaderByte = 34;

    byte[] CreateAcraStruct(byte[] message, PublicKey peerPublicKey, byte[] zoneID) throws NullArgumentException, KeyGenerationException, InvalidArgumentException, SecureMessageWrapException, SecureCellException, IOException {
        if (null == message) {
            throw new NullArgumentException("Message to encrypt is not provided");
        }

        if (null == peerPublicKey) {
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
        byte[] wrappedSymmetricKey = sm.wrap(randomSymmetricKey);

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

        output.write(header);
        output.write(throwAwayKeypair.getPublicKey().toByteArray());
        output.write(wrappedSymmetricKey);
        output.write(encryptedDataLengthArray);
        output.write(encryptedData);

        return output.toByteArray();
    }

    public class AsyncHttpPost extends AsyncTask<String, String, byte[]> {
        private byte[] message = null;// post data

        public AsyncHttpPost(byte[] data) {
            message = data;
        }

        @Override
        protected byte[] doInBackground(String... params) {
            try {
                URL httpURL = new URL(params[0]);

                HttpURLConnection connection = (HttpURLConnection) httpURL.openConnection();
                connection.setRequestMethod("POST");
                connection.setRequestProperty("Content-Type","application/octet-stream");
                connection.setDoOutput(true);
                connection.setDoInput(true);

                OutputStream os = connection.getOutputStream();
                os.write(message);
                os.flush();
                os.close();

                connection.connect();

                String m = connection.getResponseMessage();
                Log.d("SMC", "getResponseMessage = " + m);

                InputStream inputStream;

                // get stream
                if (connection.getResponseCode() < HttpURLConnection.HTTP_BAD_REQUEST) {
                    inputStream = connection.getInputStream();
                } else {
                    inputStream = connection.getErrorStream();
                }

                // parse stream
                BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(inputStream));
                String temp, response = "";
                while ((temp = bufferedReader.readLine()) != null) {
                    response += temp;
                }
                bufferedReader.close();
                return response.getBytes("UTF-8");
            }
            catch (UnsupportedEncodingException e) {
                e.printStackTrace();
            }
            catch (Exception e) {
                e.printStackTrace();
            }
            return null;
        }

        /**
         * on getting result
         */
        @Override
        protected void onPostExecute(byte[] result) {
            System.out.println("Response from server:");
            System.out.println(new String(result));
        }
    }

}
