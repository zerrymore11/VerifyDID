package com.alipay.cloudrun.controller;

//import org.apache.catalina.authenticator.DigestAuthenticator;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Calendar;
import java.util.Collections;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.alibaba.fastjson.JSONObject;
import com.alipay.cloudrun.util.Claim;
import com.alipay.cloudrun.util.CredentialSubject;
import com.alipay.cloudrun.util.DigitalEnvelopeService;
import com.alipay.cloudrun.util.ErrorCode;
import com.alipay.cloudrun.util.PlainVC;
import com.alipay.cloudrun.util.Proof;
import com.alipay.cloudrun.util.ServiceResponse;
import com.alipay.cloudrun.util.Signable;
import com.alipay.cloudrun.util.Subject;

@RestController
public class ApiController {
	@GetMapping("/issuer")
	public ServiceResponse<String> sendingVCData(String keyAlias, String pubKey, String name,String student_ID) throws Exception{
        RequestVC rvc = new RequestVC(pubKey, name, student_ID);
        Issuer iss = new Issuer();
        VCmsg vc = iss.validation(rvc);
        if (vc.member_ID.equals("-")) {
            return new ServiceResponse<>(ErrorCode.AUTHORITY_CHECK_FAILED, "Not a member");
        }
        else {
            DigitalEnvelopeService encrypter = new DigitalEnvelopeService();
            String vc_msg = iss.concatenate(vc);
            String vc_msg_sign = iss.sign(vc_msg);
            String plainText = vc_msg + "||" + vc_msg_sign;
            String cypherText = encrypter.encrypt(rvc.Costumer_DID_data, keyAlias, plainText);
            return new ServiceResponse<>(ErrorCode.SUCCESS, cypherText);
        }
	}
    @GetMapping("/test")
    public Object testJson() throws Exception{
        String id = "sjdkasdhwiqd12ffEnsaodhqadioqjoisdjiAadAqa";
        String did = "did:iifaa:8ptg4HZ7Qw9U2TymV2vpbRtqDzdP6wfuLJPXPW6pNq3U";
        String name = "Zhangsan";
        String studentID = "123456789";
        String pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsHVGMxDTiZMP2qgPaZ9jZ6hnpNErYS+Nxd/RWRu+jzyx8uFKKLnZFTawykS+BUNagq2zb+uScAl6MHWPVjsKUCZwdxipI3dZjpl7jVGSLEuX32oyr59nKlz+wGnfrsqI4Mct6eJuwxnwxZFPBAnN9XCs7qdxJunP4azlt+LQ90Gg1qSyiFIWB/xwW01ZFk4/fe9tyZ5/m/CRMCRGAU/zR1ifOJP5ZRSe9Pk3e2EJ3BRJ4uAukvRGBV2FtPl7aZDbpmGIv3yJzcG2UWq6k7QJFcOWVwfBlVj+KAXbYj9gbsv4ptM0oFcSOK9wFz5xnOySd5DcI9iRMXcTlJGSPmtS4QIDAQAB";
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date date = new Date();
        String issuanceDate = formatter.format(date);
        Calendar calendar = new GregorianCalendar();
        calendar.setTime(date);
        calendar.add(Calendar.MONTH, 120);
        Date expiration = calendar.getTime();
        String expirationDate = formatter.format(expiration);
        Subject subject = new Subject();
        subject.setName(name);
        subject.setMemberID("ZJU123456789");
        subject.setStudenID(studentID);
        Claim claim = new Claim();
        claim.setSubject(subject);
        claim.setSubject(subject);
        CredentialSubject credentialSubject = new CredentialSubject();
        credentialSubject.setID(id);
        credentialSubject.setDID(did);
        credentialSubject.setClaim(claim);
        Signable signable = new Signable();
        signable.setContext(new String[] {"www.w3.org/2018/credentials/v1", "www.w3.org/2018/credentials/examples/v1"});
        signable.setTypes(new String[] {"ZUnivBasketballCredentialType", "SelectiveDisclosureCredentialType"});
        signable.setID(id);
        signable.setIssuer("did:iifaa:JAzYiye7q1ZFXGcxW44YkKkWDemSYeWoXvituZkXPhpa");
        signable.setIssuanceDate(issuanceDate);
        signable.setExprirationDate(expirationDate);
        signable.setCredentialSubject(credentialSubject);
        Issuer iss = new Issuer();
        String proofvalue = iss.sign(JSONObject.toJSONString(signable));
        Proof proof = new Proof();
        proof.setType("Ed25519VerificationKey2018");
        proof.setCreated(issuanceDate);
        proof.setProofPurpose("ISSUE");
        proof.setVerificationMethod(did+"#keys-1");
        proof.setProofValue(proofvalue);
        PlainVC plainvc = new PlainVC();
        plainvc.setContext(new String[] {"www.w3.org/2018/credentials/v1", "www.w3.org/2018/credentials/examples/v1"});
        plainvc.setTypes(new String[] {"ZUnivBasketballCredentialType", "SelectiveDisclosureCredentialType"});
        plainvc.setID(id);
        plainvc.setIssuer("did:iifaa:JAzYiye7q1ZFXGcxW44YkKkWDemSYeWoXvituZkXPhpa");
        plainvc.setIssuanceDate(issuanceDate);
        plainvc.setExprirationDate(expirationDate);
        plainvc.setCredentialSubject(credentialSubject);
        plainvc.setProof(proof);
        DigitalEnvelopeService encrypter = new DigitalEnvelopeService();
        String ciphertext = encrypter.encrypt(pubkey, did+"#keys-1", JSONObject.toJSONString(plainvc));
        ServiceResponse<String> sr = new ServiceResponse<>(ErrorCode.SUCCESS, ciphertext);
        return JSONObject.toJSON(sr);
    }
    @GetMapping("/vc")
    public Object testService(String did, String name, String studentID, String pubkey) throws Exception{
        Issuer iss = new Issuer();
        String id = iss.generateID(10);
        // String did = "did:iifaa:8ptg4HZ7Qw9U2TymV2vpbRtqDzdP6wfuLJPXPW6pNq3U";
        // String name = "Zhangsan";
        // String studentID = "123456789";
        // String pubkey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAsHVGMxDTiZMP2qgPaZ9jZ6hnpNErYS+Nxd/RWRu+jzyx8uFKKLnZFTawykS+BUNagq2zb+uScAl6MHWPVjsKUCZwdxipI3dZjpl7jVGSLEuX32oyr59nKlz+wGnfrsqI4Mct6eJuwxnwxZFPBAnN9XCs7qdxJunP4azlt+LQ90Gg1qSyiFIWB/xwW01ZFk4/fe9tyZ5/m/CRMCRGAU/zR1ifOJP5ZRSe9Pk3e2EJ3BRJ4uAukvRGBV2FtPl7aZDbpmGIv3yJzcG2UWq6k7QJFcOWVwfBlVj+KAXbYj9gbsv4ptM0oFcSOK9wFz5xnOySd5DcI9iRMXcTlJGSPmtS4QIDAQAB";
        SimpleDateFormat formatter = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
        Date date = new Date();
        String issuanceDate = formatter.format(date);
        Calendar calendar = new GregorianCalendar();
        calendar.setTime(date);
        calendar.add(Calendar.MONTH, 120);
        Date expiration = calendar.getTime();
        String expirationDate = formatter.format(expiration);
        Subject subject = new Subject();
        subject.setName(name);
        subject.setMemberID("ZJU123456789");
        subject.setStudenID(studentID);
        Claim claim = new Claim();
        claim.setSubject(subject);
        claim.setSubject(subject);
        CredentialSubject credentialSubject = new CredentialSubject();
        credentialSubject.setID(id);
        credentialSubject.setDID(did);
        credentialSubject.setClaim(claim);
        Signable signable = new Signable();
        signable.setContext(new String[] {"www.w3.org/2018/credentials/v1", "www.w3.org/2018/credentials/examples/v1"});
        signable.setTypes(new String[] {"ZUnivBasketballCredentialType", "SelectiveDisclosureCredentialType"});
        signable.setID(id);
        signable.setIssuer("did:iifaa:JAzYiye7q1ZFXGcxW44YkKkWDemSYeWoXvituZkXPhpa");
        signable.setIssuanceDate(issuanceDate);
        signable.setExprirationDate(expirationDate);
        signable.setCredentialSubject(credentialSubject);
        String proofvalue = iss.sign(JSONObject.toJSONString(signable));
        Proof proof = new Proof();
        proof.setType("Ed25519VerificationKey2018");
        proof.setCreated(issuanceDate);
        proof.setProofPurpose("ISSUE");
        proof.setVerificationMethod(did+"#keys-1");
        proof.setProofValue(proofvalue);
        PlainVC plainvc = new PlainVC();
        plainvc.setContext(new String[] {"www.w3.org/2018/credentials/v1", "www.w3.org/2018/credentials/examples/v1"});
        plainvc.setTypes(new String[] {"ZUnivBasketballCredentialType", "SelectiveDisclosureCredentialType"});
        plainvc.setID(id);
        plainvc.setIssuer("did:iifaa:JAzYiye7q1ZFXGcxW44YkKkWDemSYeWoXvituZkXPhpa");
        plainvc.setIssuanceDate(issuanceDate);
        plainvc.setExprirationDate(expirationDate);
        plainvc.setCredentialSubject(credentialSubject);
        plainvc.setProof(proof);
        DigitalEnvelopeService encrypter = new DigitalEnvelopeService();
        String ciphertext = encrypter.encrypt(pubkey, did+"#keys-1", JSONObject.toJSONString(plainvc));
        ServiceResponse<String> sr = new ServiceResponse<>(ErrorCode.SUCCESS, ciphertext);
        return JSONObject.toJSON(sr);
    }
    @GetMapping("/second")
    public String second() {
        return "Hello,world";
    }
    
    @RequestMapping("/first")
    public String first() {
        return "Hellow,world";
    }
}

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
    // //private final String DEFAULT_PubKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAzaGujoar0cgDdHIMqK+2" +
    //         "dm0WTPmfdStU8/tkpKJcQJpIJkId3kuIhaq4ky4i0/uyXqKpwusfjT3AH6kPJqsv" +
    //         "4lz2Ti2Q8BObzf7KHNM0lmaa3orJEytGurmzXo62sfala1ucQqAO2Zndo4c1QDyr" +
    //         "pNr0QM08YC2i5bCpynz2AWijZ6w7UWwI1J0t9XJFwTpvI61r1iSewDDECcJGSQqr" +
    //         "ZqjBWG1mbwRKt6rQ+elsj5CTcJESZYNxV+VPphQeFL45Daj7jts2s/2PqnU+82qe" +
    //         "MWODVhUIsfU0senGbcbgbFSneTR29gbiqQuiuzmB2sb5v8q1bNytSVhrfQ7NR7Y4" +
    //         "wQIDAQAB" ;
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
        int nextInt;
        try (Scanner sc = new Scanner(System.in)) {
            nextInt = sc.nextInt();
        }

        String member_ID = "ZJB123456789";
        if (nextInt == 1) {
            return new VCmsg(rvc.name, rvc.student_ID,member_ID);
        }
        else {
            return new VCmsg(rvc.name, rvc.student_ID,"-");
        }
    }

    public String concatenate(VCmsg vm){
        ArrayList<String> msg_list = new ArrayList<>();
        ArrayList<String> labels = new ArrayList<>();

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

    public String generateID(int n){
        String str="abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        Random random=new Random();
        StringBuffer sb=new StringBuffer();
        for(int i=0;i<n;i++){
          int number=random.nextInt(62);
          sb.append(str.charAt(number));
        }
        return sb.toString();
    }

}