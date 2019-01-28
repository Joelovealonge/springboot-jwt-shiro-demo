package com.alonge.shirodemo.dao;


import com.alonge.shirodemo.domain.Role;
import com.alonge.shirodemo.domain.User;
import com.alonge.shirodemo.mapper.UserMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
public class UserDao {
    @Autowired
    private UserMapper userMapper;

    public User getUserByUsernameAndPassword(Map<String, String> params) {
        return userMapper.getUserByUsernameAndPassword(params);
    }

    public List<Role> getRolesByUsername(String username) {
        return userMapper.getRolesByUsername(username);
    }

}
