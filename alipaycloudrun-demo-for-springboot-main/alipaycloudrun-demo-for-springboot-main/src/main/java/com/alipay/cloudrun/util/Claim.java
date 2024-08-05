package com.alipay.cloudrun.util;

import java.io.Serializable;
public class Claim implements Serializable{
    Subject subject;
    
    public Subject getSubject(){
        return subject;
    }

    public void setSubject(Subject subject){
        this.subject = subject;
    }
}

