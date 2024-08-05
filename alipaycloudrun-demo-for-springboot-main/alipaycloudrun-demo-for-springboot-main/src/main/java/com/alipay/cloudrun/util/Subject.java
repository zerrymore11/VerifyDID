package com.alipay.cloudrun.util;

public class Subject{
    private String name;
    private String studentID;
    private String memberID;
    
    public String getName() {
        return name;
    }

    public String getStudentID() {
        return studentID;
    }

    public String getMemberID() {
        return memberID;
    }

    public void setName (String name){
        this.name = name;
    }

    public void setStudenID (String studentID){
        this.studentID = studentID;
    }

    public void setMemberID (String memberID){
        this.memberID = memberID;
    }
    
}
