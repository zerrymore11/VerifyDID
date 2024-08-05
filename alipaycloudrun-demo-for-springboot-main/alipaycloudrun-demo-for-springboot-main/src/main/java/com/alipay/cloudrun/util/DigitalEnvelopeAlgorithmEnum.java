package com.alipay.cloudrun.util;

public enum DigitalEnvelopeAlgorithmEnum {
    RSA("RSA"),
    AES_128_ECB_PKCS7Padding("AES_128_ECB_PKCS7Padding");

    private String algorithm;

    private DigitalEnvelopeAlgorithmEnum(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return this.algorithm;
    }
}
