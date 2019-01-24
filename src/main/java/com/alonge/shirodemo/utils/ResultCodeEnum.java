package com.alonge.shirodemo.utils;

/**
 * 返回情况类
 * @author wuyanlong
 */
public enum ResultCodeEnum {

    SUCCESS(200, "请求成功"),
    UNKNOWN_ERROR(415, "未知错误"),
    ERROR_TOKEN(416, "Token错误"),
    ERROR_PERMISSION(417, "没有权限"),
    ERROR_USERNAME_PASSWORD(418, "帐号或密码错误");

    private int code;
    private String message;

    ResultCodeEnum() {
    }

    ResultCodeEnum(int code, String message) {
        this.code = code;
        this.message = message;
    }

    public int getCode() {
        return code;
    }

    public void setCode(int code) {
        this.code = code;
    }

    public String getMessage() {
        return message;
    }

    public void setMessage(String message) {
        this.message = message;
    }
}
