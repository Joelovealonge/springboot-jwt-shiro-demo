package com.alonge.shirodemo.config;

import com.alonge.shirodemo.domain.Role;
import com.alonge.shirodemo.service.UserService;
import com.alonge.shirodemo.utils.JwtUtil;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.springframework.beans.factory.annotation.Autowired;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

public class UserRealm extends AuthorizingRealm {
    @Autowired
    UserService userService;

    /**
     * 授权
     * @param principalCollection 用户身份
     * @return  权限信息对象
     */
    @Override
    protected AuthorizationInfo doGetAuthorizationInfo(PrincipalCollection principalCollection) {

        // 从用户身份中得到token
        String token = (String) principalCollection.getPrimaryPrincipal();
        // 取出username
        String username = JwtUtil.getUsername(token);
        // 查询user那么对应的角色、权限，
        List<Role> roleList = userService.getRolesByUsername(username);
        Set<String> roles = new HashSet<>();
        for (Role role : roleList) {
            roles.add(role.getRoleName());
        }
        // 权限信息集合
        SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
        info.setRoles(roles);
        return info;
    }

    /**
     *
     * @param authenticationToken
     * @return 身份信息
     * @throws AuthenticationException
     */
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken authenticationToken) throws AuthenticationException {
        // 由于在自定义的过滤器中，Token的认证已经通过了，所以直接返回用户的身份
        return new SimpleAuthenticationInfo(authenticationToken.getPrincipal(), authenticationToken.getCredentials(), getName());
    }


     /*// 认证
    @Override
    protected AuthenticationInfo doGetAuthenticationInfo(AuthenticationToken token) throws AuthenticationException {
        // 获取用户信息
        String username = token.getPrincipal().toString();

        // 模拟数据库用户 密码 盐 和用户名一样
        User user = new User();
        user.setUsername(username);
        // 模拟密码密文，
        Md5Hash password = new Md5Hash(
                username, // 密码
                username, // 盐
                2
        );
        user.setPassword(password.toHex());
        user.setSalt(username);
        System.out.println(password);

        if (null == user){
            // 没有返回登录用户名对应的SimpleAuthenticationInfo对象时,就会在LoginController中抛出UnknownAccountException异常
            return null;
        }

        SimpleAuthenticationInfo info = new SimpleAuthenticationInfo(
                username, // 用户名
                user.getPassword(), // 密码
                ByteSource.Util.bytes(user.getSalt()), // 盐
                getName()
        );
        return info;
    }*/
}
