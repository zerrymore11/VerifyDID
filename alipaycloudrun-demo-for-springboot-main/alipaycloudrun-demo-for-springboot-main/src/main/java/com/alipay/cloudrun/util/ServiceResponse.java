package com.alipay.cloudrun.util;

import java.io.Serializable;

public class ServiceResponse<T> implements Serializable {
    private int code;

    private String msg;

    private T data;

    public ServiceResponse() {
    }

    public ServiceResponse(ErrorCode errorCode, T data) {
        this.code = errorCode.getCode();
        this.msg = errorCode.getCodeDesc();
        this.data = data;
    }

    public ServiceResponse(ServiceResponse serviceResponse, T data) {
        this.code = serviceResponse.getCode();
        this.msg = serviceResponse.getMsg();
        this.data = data;
    }

    public ServiceResponse(int errorCode, String errorMsg, T data) {
        this.code = errorCode;
        this.msg = errorMsg;
        this.data = data;
    }

    public int getCode() {
        return this.code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMsg() {
        return this.msg;
    }

    public void setMsg(String msg) {
        this.msg = msg;
    }

    public T getData() {
        return this.data;
    }

    public void setData(T data) {
        this.data = data;
    }

    public String toString() {
        return "ServiceResponse{code=" + this.code + ", msg='" + this.msg + '\'' + ", data=" + this.data + '}';
    }
}