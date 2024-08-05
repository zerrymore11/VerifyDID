package com.alipay.cloudrun.util;

// import java.io.Serializable;

import com.alibaba.fastjson.annotation.JSONField;

public class PlainVC {
    @JSONField(ordinal = 1)
    private String[] context;

    @JSONField(ordinal = 2)
    private String[] types;

    @JSONField(ordinal = 3)
    private String id;

    @JSONField(ordinal = 4)
    private String issuer;

    @JSONField(ordinal = 5)
    private String issuanceDate;

    @JSONField(ordinal = 6)
    private String expirationDate;

    @JSONField(ordinal = 7)
    private CredentialSubject credentialSubject;

    @JSONField(ordinal = 8)
    private Proof proof;

    public String[] getContext(){
        return context;
    }

    public String[] getTypes() {
        return types;
    }

    public String getID() {
        return id;
    }

    public String getIssuer() {
        return issuer;
    }

    public String getIssuranceDate(){
        return issuanceDate;
    }

    public String getExprirationDate() {
        return expirationDate;
    }

    public CredentialSubject getCredentialSubject() {
        return credentialSubject;
    }

    public Proof getProof(){
        return proof;
    }

    public void setContext(String[] context){
        this.context = context;
    }

    public void setTypes(String[] types) {
        this.types = types;
    }

    public void setID(String id) {
        this.id = id;
    }

    public void setIssuer(String issuer) {
        this.issuer = issuer;
    }

    public void setIssuanceDate(String issuanceDate){
        this.issuanceDate = issuanceDate;
    }

    public void setExprirationDate(String expirationDate) {
        this.expirationDate = expirationDate;
    }

    public void setCredentialSubject(CredentialSubject credentialSubject) {
        this.credentialSubject = credentialSubject;
    }

    public void setProof(Proof proof){
        this.proof = proof;
    }
}
