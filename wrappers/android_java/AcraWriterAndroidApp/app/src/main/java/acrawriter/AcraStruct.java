package acrawriter;


/**
 * AcraStruct represents binary format of encrypted data.
 * What is AcraStruct inner structure https://github.com/cossacklabs/acra/wiki/AcraStruct
 * */
public class AcraStruct {


    private byte[] data;

    /**
     * Packs AcraStruct from binary data
     *
     * @param data bytes array in format of AcraStruct (header, public key, encrypted symmetric key, encrypted data length, data length)
     */
    AcraStruct(byte[] data) {
        this.data = data;
    }

    /**
     * Returns binary data of AcraStruct
     * @return AcraStruct as byte array
     */
    public byte[] toByteArray() {
        return this.data;
    }
}