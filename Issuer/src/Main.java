import java.util.ArrayList;
import java.util.Collections;
import java.util.Arrays;
import java.nio.charset.StandardCharsets;
import java.security.*;

import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.*;
import javax.crypto.spec.GCMParameterSpec;
import java.security.NoSuchAlgorithmException;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;

import java.security.SecureRandom;
import java.io.IOException;
import java.util.Scanner;




class RequestVC {
    String Costumer_DID_data;
    String name;
    String student_ID;

    public RequestVC (String Costumer_DID_data, String name, String student_ID){
        this.Costumer_DID_data = Costumer_DID_data;
        this.name = name;
        this.student_ID = student_ID;
    }

}

class VCmsg {
    String name;
    String student_ID;
    String member_ID;
    public VCmsg (String name, String student_ID, String member_ID) {
        this.name = name;
        this.student_ID = student_ID;
        this.member_ID = member_ID;
    }
}
class Issuer {
    private final String DEFAULT_PubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzaGujoar0cgDdHIMqK+2" +
            "dm0WTPmfdStU8/tkpKJcQJpIJkId3kuIhaq4ky4i0/uyXqKpwusfjT3AH6kPJqsv" +
            "4lz2Ti2Q8BObzf7KHNM0lmaa3orJEytGurmzXo62sfala1ucQqAO2Zndo4c1QDyr" +
            "pNr0QM08YC2i5bCpynz2AWijZ6w7UWwI1J0t9XJFwTpvI61r1iSewDDECcJGSQqr" +
            "ZqjBWG1mbwRKt6rQ+elsj5CTcJESZYNxV+VPphQeFL45Daj7jts2s/2PqnU+82qe" +
            "MWODVhUIsfU0senGbcbgbFSneTR29gbiqQuiuzmB2sb5v8q1bNytSVhrfQ7NR7Y4" +
            "wQIDAQAB" ;
    private final String DEFAULT_PrvKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDNoa6OhqvRyAN0" +
            "cgyor7Z2bRZM+Z91K1Tz+2SkolxAmkgmQh3eS4iFqriTLiLT+7JeoqnC6x+NPcAf" +
            "qQ8mqy/iXPZOLZDwE5vN/soc0zSWZpreiskTK0a6ubNejrax9qVrW5xCoA7Zmd2j" +
            "hzVAPKuk2vRAzTxgLaLlsKnKfPYBaKNnrDtRbAjUnS31ckXBOm8jrWvWJJ7AMMQJ" +
            "wkZJCqtmqMFYbWZvBEq3qtD56WyPkJNwkRJlg3FX5U+mFB4UvjkNqPuO2zaz/Y+q" +
            "dT7zap4xY4NWFQix9TSx6cZtxuBsVKd5NHb2BuKpC6K7OYHaxvm/yrVs3K1JWGt9" +
            "Ds1HtjjBAgMBAAECggEAEpFqyjrrO/Ou1YPQ6dCIDjSL2CKNnWPEIDiPSMsnv7uk" +
            "D98A2chXSRP2kRplkbUU0Qp+Ks2BbrG97f3y53UmIJoasZ+CtXMH1XeQN5RzbLCn" +
            "g7iOL0Qaob96rMCqoEebKKZqkJzptQjO+eEP1BTxE4n5QVARshuc2IHLKy99JU5B" +
            "9hB8c10yq8t/OEX+ezkhTvki/m+MMiddoWL0qzbdKfio/aoNmBRdiL9GzWqTEuCE" +
            "aZAzf3bZdos7o7v75WSQCJWnjHWUUNynioowFCx33uxJ80auZIrW8IECbSQBV5u+" +
            "CxK/cqepk7iW3HJGRECqTlUIUAjNBJyr6Qcaa2UBAwKBgQDpOe7yrjjlb3LLs9Ke" +
            "YREXlhKUUu9iQvlUWMzyhCGc8n+omhdFPAY0ep3/WkMOBdOD+pAfrgWd9r392NME" +
            "ADT9QK86zHEev/TttIltl2r+Uv+LUNH/HTDgynAj28Ath4b9NA9iBzw+qp8cmXj+" +
            "RP7z7WSaxqmrTCyzT3xhqpUGVwKBgQDhtfM4TnS9N7Fov3gu7P5pyEnEv9dJStTb" +
            "sr/1IfHfRb5zQ3UG8UFBjr0VQDft5pU+CHeBEWl/QJ8aasqS1gdLMc3rJf3EpWH+" +
            "5PQlsuz0zi7d2JOmjwK3ICsZ6JN8eAvhKM/eILNXv1+zh9vz4mzJbNOJPPd1mkPf" +
            "GGkU1g/apwKBgGxMWoiWHhVsCwJMHiEtMaKiLT5yxHX8Y4qnMYPrlzAp6t1/sA6W" +
            "MMttpLBOWZTJX86JKyOKy1DuooqdhF73OaPfxX6oMF73A+TdUHNzPFucbs1iWiD8" +
            "jRXU6v27rSF3LVemNP5wHal70SaWnXh00W6zbWPxnBfO53LcFgXEEC9BAoGBAKsG" +
            "zrwcntJ9r906MBwGkiSfkl4WK1Aq9q1efZuGVBslYtE+DR/skNDXEqlWlsqaTP3L" +
            "NppDElhNJAHFZ6fpq28r1udWSzrFQkL9Q46JTImW7eZF5GNxu9H8+wvPsmm/IOlE" +
            "nnWm+54CscZ8rIrZSCs8XfGAk9W1xbX3bjBOn4bDAoGAI0U/EMbeFqzqf0iIGVfF" +
            "dVsqLVCyhYcS8P7dv52K6dsKorqUgoNmVkdj/vKf9tn8j1cJgfijhvN6MuPOGDn4" +
            "KGzeuyNbYnmMq8RhPLGHpx7hG3VBelfFFAWiPCMfftQAmPsAEL/UT25IMH2o2Vdk" +
            "dz9brHbcDNksp9cuA52gI/8=";

    private PublicKey getPublicKeyFromString(String publicKeyString) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(publicKeyString);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(keySpec);
    }
    private PrivateKey getPrivateKeyFromString(String privateKeyString) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(privateKeyString);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(keySpec);
    }
    public String sign(String msg) throws Exception {
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initSign(getPrivateKeyFromString(this.DEFAULT_PrvKey));

        // 更新要签名的数据
        sig.update(msg.getBytes());

        // 签名
        byte[] signature = sig.sign();

        // 基于Base64编码以便打印和传输
        //        System.out.println("Signature: " + base64Signature);

        return Base64.getEncoder().encodeToString(signature);
    }

    public VCmsg validation(RequestVC rvc){
        System.out.println("The student id is " + rvc.student_ID + ", name is " + rvc.name +
                "\n waiting for validation..[1 for validated/0 for not]");
        Scanner sc = new Scanner(System.in);
        int nextInt = sc.nextInt();
        String member_ID = "ZJB123456789";
        if (nextInt == 1) {
            return new VCmsg(rvc.name, rvc.student_ID,member_ID);
        }
        else {
            return new VCmsg(rvc.name, rvc.student_ID,"-");
        }
    }

    public String concatenate(VCmsg vm){
        ArrayList<String> msg_list = new ArrayList<String>();
        ArrayList<String> labels = new ArrayList<String>();

        msg_list.add(vm.name);
        msg_list.add(vm.student_ID);
        msg_list.add(vm.member_ID);

        labels.add("name");
        labels.add("student_ID");
        labels.add("member_ID");

        int i1 = 0;
        int i2 = 0;
        int i3 = 0;

        while (i1 < msg_list.get(0).length() && i1 < msg_list.get(1).length()){
            if (msg_list.get(0).charAt(i1) > msg_list.get(1).charAt(i1)){
                Collections.swap(msg_list,0,1);
                Collections.swap(labels,0,1);
                break;
            }
            i1 = i1 + 1;
        }

        while (i2 < msg_list.get(1).length() && i2 < msg_list.get(2).length()){
            if (msg_list.get(1).charAt(i2) > msg_list.get(2).charAt(i2)){
                Collections.swap(msg_list,1,2);
                Collections.swap(labels,1,2);
                break;
            }
            i2 = i2 + 1;
        }

        while (i3 < msg_list.get(0).length() && i3 < msg_list.get(1).length()){
            if (msg_list.get(0).charAt(i3) > msg_list.get(1).charAt(i3)){
                Collections.swap(msg_list,0,1);
                Collections.swap(labels,0,1);
                break;
            }
            i3 = i3 + 1;
        }

        return labels.get(0) + "=" + msg_list.get(0) + "&" + labels.get(1) + "=" + msg_list.get(1) + "&" +
                labels.get(2) + "=" + msg_list.get(2);
    }

    public String SEnc (String msg, String key, String algorithm) throws Exception {
        Cipher cipher = Cipher.getInstance(algorithm);
        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(key), algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);
        byte[] encryptedBytes = cipher.doFinal(msg.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String SDec (String encrypted, String key, String algorithm) throws Exception{
        Cipher cipher = Cipher.getInstance(algorithm);
        SecretKeySpec secretKeySpec = new SecretKeySpec(Base64.getDecoder().decode(key), algorithm);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encrypted));
        return new String(decrypted);
    }

    public String AEnc (String msg, String pubkey, String algorithm) throws Exception{
        PublicKey PubKey = this.getPublicKeyFromString(pubkey);
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, PubKey);
        byte[] encrypted = cipher.doFinal(msg.getBytes());

        return Base64.getEncoder().encodeToString(encrypted);
    }

    public String ADec (String encrypted, String prvkey, String algorithm) throws Exception {
        PrivateKey PrvKey = this.getPrivateKeyFromString(prvkey);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, PrvKey);
        byte[] decrypted = cipher.doFinal(Base64.getDecoder().decode(encrypted));
        return new String(decrypted);
    }

    public String[] VCDataGeneration (String VC_msg, String VC_msg_sign,
                                      String envelop_key, String Customer_PubKey) throws Exception {
        String encrypted_VCmsg = SEnc(VC_msg + "&Sign=" + VC_msg_sign, envelop_key, "AES");
        String encrypted_envelop_key = AEnc(envelop_key,Customer_PubKey,"RSA");

        return new String[]{encrypted_VCmsg, encrypted_envelop_key};
    }

}

class EnvelopKeyGenerator {
    private static final String KEY_ALGORITHM = "AES";

    // 加密/解密算法/工作模式/填充方式
    private static final String CIPHER_ALGORITHM = "AES/ECB/PKCS5Padding";

    // 生成密钥
    public String generateAESKey() throws Exception {
        KeyGenerator keyGenerator = KeyGenerator.getInstance(KEY_ALGORITHM);
        keyGenerator.init(128, new SecureRandom()); // 192 and 256 bits may not be available
        SecretKey secretKey = keyGenerator.generateKey();
        return Base64.getEncoder().encodeToString(secretKey.getEncoded());
    }

}

public class Main {
    public static void main(String[] args) throws Exception {
        //Start of testing sample code, customer keys are generated by the following,And set the name and student_ID
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);

        KeyPair pair = keyGen.generateKeyPair();
        PublicKey publicKey = pair.getPublic();
        PrivateKey privateKey = pair.getPrivate();

        String Customer_PubKey = Base64.getEncoder().encodeToString(publicKey.getEncoded());
        String Customer_PrvKey = Base64.getEncoder().encodeToString(privateKey.getEncoded());

        String name = "Zhang San";
        String student_ID = "ZJU1234567";
        //End of testing sample code

        EnvelopKeyGenerator ekg = new EnvelopKeyGenerator();

        String envelop_key = ekg.generateAESKey();

        Issuer isu = new Issuer();

        RequestVC rvc = new RequestVC("DEFAULT", name,student_ID);
        VCmsg VC_message = isu.validation(rvc);

        String VC_msg = isu.concatenate(VC_message);

        String VC_msg_sign = isu.sign(VC_msg);

        String[] vcData = isu.VCDataGeneration(VC_msg,VC_msg_sign,envelop_key, Customer_PubKey);

        //Decryption testing
        String envelop_key_original = isu.ADec(vcData[1], Customer_PrvKey, "RSA");

        String original_msg = isu.SDec(vcData[0], envelop_key_original,"AES");

        System.out.println(original_msg);

    }
}