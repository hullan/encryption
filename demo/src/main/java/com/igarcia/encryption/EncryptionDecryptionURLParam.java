package com.igarcia.encryption;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class EncryptionDecryptionURLParam {
    public static final String FORMAT = "yyyy-MM-dd'T'HH:mm:ssZ";

    public static void main(String[] args) throws Exception {
        SimpleDateFormat sdf = new SimpleDateFormat(FORMAT);
        String timestamp = sdf.format(new Date());

        String constantValue = "FacingIssuesOnIT";
        String sessionId = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

        String tokenStr = constantValue + "$" + timestamp + "/06$" + sessionId;

        System.out.println(tokenStr);

        byte[] keyBytes = new byte[] { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
                0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };

        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");

        SecretKeySpec key = new SecretKeySpec(keyBytes, "AES");

        // encryption url
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] cipherText = cipher.doFinal(tokenStr.getBytes());
        System.out.println("encrypted token size:" + cipherText.length);
        // Encode Character which are not allowed on URL
        String encodedTxt = Base64.encodeBase64URLSafeString(cipherText);

        System.out.println("EncodedEncryptedToken : " + encodedTxt);

        // decryption url
        cipher.init(Cipher.DECRYPT_MODE, key);
        String decodeStr = URLDecoder.decode(
                encodedTxt,
                StandardCharsets.UTF_8.toString());
        System.out.println("URL Decoder String :" + decodeStr);
        // Decode URl safe to base 64
        byte[] base64decodedTokenArr = Base64.decodeBase64(decodeStr.getBytes());

        byte[] decryptedPassword = cipher.doFinal(base64decodedTokenArr);
        // byte[] decryptedPassword = cipher.doFinal(decodeStr.getBytes());
        String decodeTxt = new String(decryptedPassword);
        System.out.println("Token after decryption: " + decodeTxt);

    }

}
