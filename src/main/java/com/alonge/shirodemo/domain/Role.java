package com.alonge.shirodemo.domain;

public class Role {
    private String roleName;

    public Role(String roleName) {
        this.roleName = roleName;
    }

    public String getRoleName() {
        return roleName;
    }

    public Role() {
    }

    public void setRoleName(String roleName) {
        this.roleName = roleName;
    }
}
