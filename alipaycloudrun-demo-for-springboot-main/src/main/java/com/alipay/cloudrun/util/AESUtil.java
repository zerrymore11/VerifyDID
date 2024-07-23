package com.alipay.cloudrun.util;

import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class AESUtil {
    public AESUtil() {
    }

    public static String encrypt(String plainText, String key) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (null != plainText && null != key) {
            byte[] content = plainText.getBytes("UTF-8");
            byte[] passwd = Base64.getDecoder().decode(key);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(passwd, "AES");
            cipher.init(1, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(content));
        } else {
            return null;
        }
    }

    public static String decrypt(String cipherText, String key) throws UnsupportedEncodingException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        if (null != cipherText && null != key) {
            byte[] content = Base64.getDecoder().decode(cipherText);
            byte[] passwd = Base64.getDecoder().decode(key);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(passwd, "AES");
            cipher.init(2, secretKey);
            return new String(cipher.doFinal(content), "UTF-8");
        } else {
            return null;
        }
    }

    public static String generateSymKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        SecureRandom secureRandom = new SecureRandom();
        keyGenerator.init(128, secureRandom);
        SecretKey key = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
}