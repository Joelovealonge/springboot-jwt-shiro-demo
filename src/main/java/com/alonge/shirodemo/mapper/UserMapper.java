package com.alonge.shirodemo.mapper;

import com.alonge.shirodemo.domain.Role;
import com.alonge.shirodemo.domain.User;
import org.apache.ibatis.annotations.Mapper;

import java.util.List;
import java.util.Map;

@Mapper
public interface UserMapper {

    User getUserByUsernameAndPassword(Map<String, String> params);

    List<Role> getRolesByUsername(String username);
}
