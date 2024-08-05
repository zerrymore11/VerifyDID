package com.alipay.cloudrun.util;

import com.alibaba.fastjson.annotation.JSONField;
public class CredentialSubject {

    @JSONField(ordinal=1)
    private String id;

    @JSONField(ordinal=2)
    private String did;

    @JSONField(ordinal=3)
    private Claim claim;

    public String getID (){
        return id;
    }

    public String getDID () {
        return did;
    }
    public Claim getClaim() {
        return claim;
    }
    public void setID (String id){
        this.id = id;
    }

    public void setDID (String did) {
        this.did = did;
    }

    public void setClaim (Claim claim){
        this.claim = claim;
    }
}
