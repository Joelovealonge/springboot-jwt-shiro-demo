package com.alonge.shirodemo.service;

import com.alonge.shirodemo.dao.UserDao;
import com.alonge.shirodemo.domain.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class UserService {
    @Autowired
    private UserDao userDao;

    public boolean login(Map<String, String> params) {
        return null == userDao.getUserByUsernameAndPassword(params) ? false : true;
    }

    public List<Role> getRolesByUsername(String username) {
        return userDao.getRolesByUsername(username);
    }
}
