package com.alipay.cloudrun.util;

public class DigitalEnvelopeModel {
    private String algorithm;
    private String keyAlias;
    private String cipher;
    private String keyCipher;

    public DigitalEnvelopeModel() {
    }

    public String getAlgorithm() {
        return this.algorithm;
    }

    public void setAlgorithm(String algorithm) {
        this.algorithm = algorithm;
    }

    public String getKeyAlias() {
        return this.keyAlias;
    }

    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
    }

    public String getCipher() {
        return this.cipher;
    }

    public void setCipher(String cipher) {
        this.cipher = cipher;
    }

    public String getKeyCipher() {
        return this.keyCipher;
    }

    public void setKeyCipher(String keyCipher) {
        this.keyCipher = keyCipher;
    }

    public static class SymmetricKey {
        private String algorithm;
        private String symKey;

        public SymmetricKey() {
        }

        public String getAlgorithm() {
            return this.algorithm;
        }

        public void setAlgorithm(String algorithm) {
            this.algorithm = algorithm;
        }

        public String getSymKey() {
            return this.symKey;
        }

        public void setSymKey(String symKey) {
            this.symKey = symKey;
        }

        public String toString() {
            return "SymmetricKey{algorithm='" + this.algorithm + '\'' + ", symKey='" + this.symKey + '\'' + '}';
        }
    }
}
