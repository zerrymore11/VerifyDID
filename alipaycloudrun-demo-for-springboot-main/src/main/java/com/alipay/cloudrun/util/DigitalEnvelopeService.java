package com.alipay.cloudrun.util;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

import com.alibaba.fastjson.JSONObject;

public class DigitalEnvelopeService{
     public DigitalEnvelopeService() {
    }

    public String encrypt(String publicKey, String keyAlias, String plainText) throws Exception {
        String symKey = AESUtil.generateSymKey();
        String cipherText = AESUtil.encrypt(plainText, symKey);
        DigitalEnvelopeModel digitalEnvelopeModel = new DigitalEnvelopeModel();
        DigitalEnvelopeModel.SymmetricKey symmetricKey = new DigitalEnvelopeModel.SymmetricKey();
        symmetricKey.setAlgorithm(DigitalEnvelopeAlgorithmEnum.AES_128_ECB_PKCS7Padding.getAlgorithm());
        symmetricKey.setSymKey(symKey);
        byte[] keyCipherBytes = RSAUtils.encryptByPublicKey(JSONObject.toJSONString(symmetricKey).getBytes(StandardCharsets.UTF_8), publicKey);
        String keyCipher = Base64.getEncoder().encodeToString(keyCipherBytes);
        digitalEnvelopeModel.setAlgorithm(DigitalEnvelopeAlgorithmEnum.RSA.getAlgorithm());
        digitalEnvelopeModel.setKeyAlias(keyAlias);
        digitalEnvelopeModel.setCipher(cipherText);
        digitalEnvelopeModel.setKeyCipher(keyCipher);
        return JSONObject.toJSONString(digitalEnvelopeModel);
    }

    public String decrypt(String digitalEnvelopeModelStr, String privateKey) throws Exception {
        DigitalEnvelopeModel digitalEnvelopeModel = (DigitalEnvelopeModel)JSONObject.parseObject(digitalEnvelopeModelStr, DigitalEnvelopeModel.class);
        String encryptAESKeyStr = digitalEnvelopeModel.getKeyCipher();
        String encryptVerifiablePresentationStr = digitalEnvelopeModel.getCipher();
        String aesSymKey = this.getAesSymKey(encryptAESKeyStr, privateKey);
        return AESUtil.decrypt(encryptVerifiablePresentationStr, aesSymKey);
    }

    private String getAesSymKey(String keyCipher, String privateKey) throws Exception{
        String aesSymKey = null;
        
        byte[] keyPlain = RSAUtils.decryptByPrivateKey(Base64.getDecoder().decode(keyCipher), privateKey);
        DigitalEnvelopeModel.SymmetricKey symmetricKey = (DigitalEnvelopeModel.SymmetricKey)JSONObject.parseObject(new String(keyPlain, StandardCharsets.UTF_8), DigitalEnvelopeModel.SymmetricKey.class);
        aesSymKey = symmetricKey.getSymKey();

        return aesSymKey;
    }
}