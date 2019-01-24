package com.alonge.shirodemo.utils;

public class SucessResult<T> extends Result<T> {

    public SucessResult() {
    }

    public SucessResult(String code, String message, T data) {
        super(ResultCodeEnum.SUCCESS.getCode(), ResultCodeEnum.SUCCESS.getMessage(), data);
    }
}
