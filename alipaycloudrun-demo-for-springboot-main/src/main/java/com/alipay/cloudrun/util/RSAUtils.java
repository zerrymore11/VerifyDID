package com.alipay.cloudrun.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource.PSpecified;

public class RSAUtils {
    public static final String KEY_ALGORITHM = "RSA";
    public static final String SIGNATURE_ALGORITHM_MD5 = "MD5withRSA";
    public static final String SIGNATURE_ALGORITHM_SHA256 = "SHA256WithRSA";
    private static final String PUBLIC_KEY = "RSAPublicKey";
    private static final String PRIVATE_KEY = "RSAPrivateKey";
    private static final int MAX_ENCRYPT_BLOCK_1024 = 117;
    private static final int MAX_DECRYPT_BLOCK_1024 = 128;
    private static final int MAX_ENCRYPT_BLOCK_2048 = 245;
    private static final int MAX_DECRYPT_BLOCK_2048 = 256;

    public RSAUtils() {
    }

    private static byte[] rsaEncryptWithOAEP(byte[] data, String publicKey, String algorithm) throws GeneralSecurityException, IOException {
        byte[] publicKeyDer = Base64.getDecoder().decode(publicKey);
        PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(publicKeyDer));
        Cipher cipher = buildCipherWithEncrypt(algorithm, pubKey);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        for(int offSet = 0; inputLen - offSet > 0; offSet += 245) {
            byte[] cache;
            if (inputLen - offSet > 245) {
                cache = cipher.doFinal(data, offSet, 245);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }

            out.write(cache, 0, cache.length);
        }

        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    public static byte[] rsaDecryptWithOAEP(byte[] encryptedData, String privateKey, String algorithm) throws GeneralSecurityException, IOException {
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PrivateKey privateK = KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(keyBytes));
        Cipher cipher = buildCipherWithDecrypt(algorithm, privateK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        for(int offSet = 0; inputLen - offSet > 0; offSet += 256) {
            byte[] cache;
            if (inputLen - offSet > 256) {
                cache = cipher.doFinal(encryptedData, offSet, 256);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }

            out.write(cache, 0, cache.length);
        }

        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    private static Cipher buildCipherWithEncrypt(String algorithm, PublicKey publicKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher;
        OAEPParameterSpec oaepParams;
        switch (algorithm) {
            case "RSAES_OAEP_SHA_1":
                cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
                oaepParams = new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSpecified.DEFAULT);
                cipher.init(1, publicKey, oaepParams);
                break;
            case "RSAES_OAEP_SHA_256":
                cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSpecified.DEFAULT);
                cipher.init(1, publicKey, oaepParams);
                break;
            default:
                throw new UnsupportedOperationException(String.format("algorithm '%s' not support.", algorithm));
        }

        return cipher;
    }

    private static Cipher buildCipherWithDecrypt(String algorithm, PrivateKey privateKey) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, InvalidAlgorithmParameterException {
        Cipher cipher;
        OAEPParameterSpec oaepParams;
        switch (algorithm) {
            case "RSAES_OAEP_SHA_1":
                cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-1AndMGF1Padding");
                oaepParams = new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSpecified.DEFAULT);
                cipher.init(2, privateKey, oaepParams);
                break;
            case "RSAES_OAEP_SHA_256":
                cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
                oaepParams = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSpecified.DEFAULT);
                cipher.init(2, privateKey, oaepParams);
                break;
            default:
                throw new UnsupportedOperationException(String.format("algorithm '%s' not support.", algorithm));
        }

        return cipher;
    }

    public static Map<String, Object> genKeyPair() throws Exception {
        KeyPairGenerator keyPairGen = KeyPairGenerator.getInstance("RSA");
        keyPairGen.initialize(2048);
        KeyPair keyPair = keyPairGen.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        Map<String, Object> keyMap = new HashMap(2);
        keyMap.put("RSAPublicKey", publicKey);
        keyMap.put("RSAPrivateKey", privateKey);
        return keyMap;
    }

    public static String sign(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        byte[] sign = sign(data, keyBytes);
        return Base64.getEncoder().encodeToString(sign);
    }

    public static String signBase64Url(byte[] data, String privateKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        byte[] sign = sign(data, keyBytes);
        return Base64.getUrlEncoder().encodeToString(sign);
    }

    public static byte[] sign(byte[] data, byte[] privateKey) throws Exception {
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(privateKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initSign(privateK);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verify(byte[] data, String publicKey, String sign) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKey);
        byte[] signBytes = Base64.getDecoder().decode(sign);
        return verify(data, keyBytes, signBytes);
    }

    public static boolean verifyBase64Url(byte[] data, String publicKey, String sign) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKey);
        byte[] signBytes = Base64.getUrlDecoder().decode(sign);
        return verify(data, keyBytes, signBytes);
    }

    public static boolean verify(byte[] data, byte[] publicKey, byte[] sign) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publicKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicK = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance("SHA256WithRSA");
        signature.initVerify(publicK);
        signature.update(data);
        return signature.verify(sign);
    }

    public static byte[] decryptByPrivateKey(byte[] encryptedData, String privateKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKey);
        PKCS8EncodedKeySpec pkcs8KeySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
        Key privateK = keyFactory.generatePrivate(pkcs8KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm(), "SunJCE");
        cipher.init(2, privateK);
        int inputLen = encryptedData.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        for(int offSet = 0; inputLen - offSet > 0; offSet += 256) {
            byte[] cache;
            if (inputLen - offSet > 256) {
                cache = cipher.doFinal(encryptedData, offSet, 256);
            } else {
                cache = cipher.doFinal(encryptedData, offSet, inputLen - offSet);
            }

            out.write(cache, 0, cache.length);
        }

        byte[] decryptedData = out.toByteArray();
        out.close();
        return decryptedData;
    }

    public static byte[] encryptByPublicKey(byte[] data, String publicKey) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKey);
        X509EncodedKeySpec x509KeySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
        Key publicK = keyFactory.generatePublic(x509KeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm(), "SunJCE");
        cipher.init(1, publicK);
        int inputLen = data.length;
        ByteArrayOutputStream out = new ByteArrayOutputStream();

        for(int offSet = 0; inputLen - offSet > 0; offSet += 245) {
            byte[] cache;
            if (inputLen - offSet > 245) {
                cache = cipher.doFinal(data, offSet, 245);
            } else {
                cache = cipher.doFinal(data, offSet, inputLen - offSet);
            }

            out.write(cache, 0, cache.length);
        }

        byte[] encryptedData = out.toByteArray();
        out.close();
        return encryptedData;
    }

    public static String getPrivateKey(Map<String, Object> keyMap) {
        Key key = (Key)keyMap.get("RSAPrivateKey");
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }

    public static String getPublicKey(Map<String, Object> keyMap) {
        Key key = (Key)keyMap.get("RSAPublicKey");
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
}