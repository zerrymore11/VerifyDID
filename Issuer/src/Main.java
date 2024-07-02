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
    private final String DEFAULT_PubKey = Issuer_PubKey ;
    private final String DEFAULT_PrvKey = Issuer_PrvKey;

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
