package com.cossacklabs.acrawriter_example;

import android.os.AsyncTask;
import android.os.Bundle;
import android.support.v7.app.AppCompatActivity;
import android.util.Base64;
import android.util.Log;

import com.cossacklabs.acrawriter.AcraStruct;
import com.cossacklabs.acrawriter.AcraWriter;
import com.cossacklabs.themis.InvalidArgumentException;
import com.cossacklabs.themis.KeyGenerationException;
import com.cossacklabs.themis.NullArgumentException;
import com.cossacklabs.themis.PublicKey;
import com.cossacklabs.themis.SecureCellException;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;

public class MainActivityAcraStructExample extends AppCompatActivity {

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        try {
            // use to generate AcraStruct and log it
            generateAcraStructLocally();

            // use with running AcraTranslator
//            generateAndSendAcraStruct();

        } catch (InvalidArgumentException | NullArgumentException | SecureCellException e) {
            e.printStackTrace();
        }
    }

    // Generate storage keys, AcraWriter is using <client_id>_storage.pub public key
    // https://docs.cossacklabs.com/acra/security-controls/key-management/operations/generation/#12-generating-transport-and-encryption-keys
    void generateAcraStructLocally() throws SecureCellException, NullArgumentException, InvalidArgumentException {
        String message = "local acrastruct";

        String acraTranslatorPublicKey = "VUVDMgAAAC240mpnAx8FSrZxhVNPsnhhZFYAm0+ARiRDdXPKAW0vI/2AY0QM";
        PublicKey publicKey = new PublicKey(Base64.decode(acraTranslatorPublicKey.getBytes(), Base64.NO_WRAP));

        try {
            AcraWriter aw = new AcraWriter();
            AcraStruct acraStruct = aw.createAcraStruct(message.getBytes(), publicKey, null);

            String encodedString = Base64.encodeToString(acraStruct.toByteArray(), Base64.NO_WRAP);
            Log.d("SMC", "acrastruct in base64 = " + encodedString);

        } catch (KeyGenerationException | IOException e) {
            e.printStackTrace();
        }
    }

    // Generate storage keys, AcraWriter is using <client_id>_storage.pub public key
    // https://docs.cossacklabs.com/acra/security-controls/key-management/operations/generation/#12-generating-transport-and-encryption-keys
    void generateAndSendAcraStruct() throws SecureCellException, NullArgumentException, InvalidArgumentException {
        String message = "hello message";

        String acraTranslatorPublicKey = "VUVDMgAAAC240mpnAx8FSrZxhVNPsnhhZFYAm0+ARiRDdXPKAW0vI/2AY0QM";
        PublicKey publicKey = new PublicKey(Base64.decode(acraTranslatorPublicKey.getBytes(), Base64.NO_WRAP));

        String URL = "http://10.0.2.2:9494/v1/decrypt";

        try {
            AcraWriter aw = new AcraWriter();
            AcraStruct acraStruct = aw.createAcraStruct(message.getBytes(), publicKey, null);

            // sending acrastructs will work in AcraConnector and AcraTranslator are up and running, and listening on localhost
            AsyncHttpPost asyncHttpPost = new AsyncHttpPost(acraStruct.toByteArray());
            asyncHttpPost.execute(URL);

        } catch (KeyGenerationException | IOException e) {
            e.printStackTrace();
        }
    }

    private class AsyncHttpPost extends AsyncTask<String, String, byte[]> {
        private byte[] message = null;// post data

        AsyncHttpPost(byte[] data) {
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

                // get stream
                InputStream inputStream;
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
            } catch (Exception e) {
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
