package com.alonge.shirodemo.domain;

import org.apache.shiro.authc.AuthenticationToken;

/**
 * @author wuyanlong
 * @desc 该类进行包装Token对象
 */
public class JwtToken implements AuthenticationToken{

    private String token;

    public JwtToken(String token) {
        this.token = token;
    }

    @Override
    public Object getPrincipal() {
        return token;
    }

    @Override
    public Object getCredentials() {
        return token;
    }
}
