/*
     *
     * BH Apps
     * version 0.0.2
     * Contains methods for encrypting & decrypting passed strings
     * bhapps.utilitools.security.java.security
     *
*/

package bhapps.utilitools.security.java.security.encryption;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class EncryptDecrypt {

    private static final byte[] keyValue =
            new byte[]{'c', 'o', 'd', 'i', 'n', 'g', 'a', 'f', 'f', 'a', 'i', 'r', 's', 'c', 'o', 'm'};

    /*
     *
     * getEncryptedStringFromString(string_to_encrypt)
     * get encrypted string from passed string value
     * bhapps.utilitools.security.java.security.encryption.EncryptDecrypt.getEncryptedStringFromString(string_to_encrypt)
     * returns String
     *
    */

    public static String getEncryptedStringFromString(String string_to_encrypt)
            throws Exception {
        byte[] rawKey = getRawKey();
        byte[] result = encrypt(rawKey, string_to_encrypt.getBytes());
        return toHex(result);
    }

    /*
     *
     * getDecryptedStringFromString(encrypted_string_to_decrypt)
     * get decrypted string from passed encrypted string value
     * bhapps.utilitools.security.java.security.encryption.EncryptDecrypt.getDecryptedStringFromString(encrypted_string_to_decrypt)
     * returns String
     *
    */

    public static String getDecryptedStringFromString(String encrypted_string_to_decrypt)
            throws Exception {

        byte[] enc = toByte(encrypted_string_to_decrypt);
        byte[] result = decrypt(enc);
        return new String(result);
    }

    private static byte[] getRawKey() throws Exception {
        SecretKey key = new SecretKeySpec(keyValue, "AES");
        byte[] raw = key.getEncoded();
        return raw;
    }

    private static byte[] encrypt(byte[] raw, byte[] clear) throws Exception {
        SecretKey skeySpec = new SecretKeySpec(raw, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec);
        byte[] encrypted = cipher.doFinal(clear);
        return encrypted;
    }

    private static byte[] decrypt(byte[] encrypted)
            throws Exception {
        SecretKey skeySpec = new SecretKeySpec(keyValue, "AES");
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec);
        byte[] decrypted = cipher.doFinal(encrypted);
        return decrypted;
    }

    public static byte[] toByte(String hexString) {
        int len = hexString.length() / 2;
        byte[] result = new byte[len];
        for (int i = 0; i < len; i++)
            result[i] = Integer.valueOf(hexString.substring(2 * i, 2 * i + 2),
                    16).byteValue();
        return result;
    }

    public static String toHex(byte[] buf) {
        if (buf == null)
            return "";
        StringBuffer result = new StringBuffer(2 * buf.length);
        for (int i = 0; i < buf.length; i++) {
            appendHex(result, buf[i]);
        }
        return result.toString();
    }

    private final static String HEX = "0123456789ABCDEF";
    private static void appendHex(StringBuffer sb, byte b) {
        sb.append(HEX.charAt((b >> 4) & 0x0f)).append(HEX.charAt(b & 0x0f));
    }
}

