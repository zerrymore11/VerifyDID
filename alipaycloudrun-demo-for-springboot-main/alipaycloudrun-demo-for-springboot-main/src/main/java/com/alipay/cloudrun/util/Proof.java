package com.alipay.cloudrun.util;

import com.alibaba.fastjson.annotation.JSONField;

public class Proof {
    @JSONField(ordinal=1)
    String type;

    @JSONField(ordinal=2)
    String created;

    @JSONField(ordinal=3)
    String proofPurpose;

    @JSONField(ordinal=4)
    String verificationMethod;

    @JSONField(ordinal=5)
    String proofValue;

    public String getType(){
        return type;
    }

    public String getCreated() {
        return created;
    }

    public String getProofPurpose() {
        return proofPurpose;
    }

    public String getVerificationMethod(){
        return verificationMethod;
    }

    public String getProofValue(){
        return proofValue;
    }

    public void setType(String type){
        this.type = type;
    }

    public void setCreated(String created){
        this.created = created;
    }

    public void setProofPurpose(String proofPurpose){
        this.proofPurpose = proofPurpose;
    }

    public void setVerificationMethod(String verificationMethod){
        this.verificationMethod = verificationMethod;
    }

    public void setProofValue(String proofValue){
        this.proofValue = proofValue;
    }

}
