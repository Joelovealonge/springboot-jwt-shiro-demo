# 认证和授权
## shiro基础
shiro是一个强大的安全框架。提供了认证、授权、会话管理等功能。

本文只介绍认证和授权模块。

`Authentication`: 身份认证/登录，验证用户是不是拥有访问系统的身份。

`Authorization`: 授权，即权限认证，简单而言就是判断用户能访问的资源。

我们先从外部来看看shiro：
`Subject` : 简单而言，是所有与系统交互的东西。
`SecurityManager`: 安全管理器，可以看做是大脑，所以的安全操作都会委托给SecurityManager，其管理着所有Subject，是subject与其它组件交流的枢纽。
`Realm`: 由于**shiro不回去维护用户、权限**。那么shiro是如何知道我们系统的用户、权限信息呢？ **shiro正是从Realm获取安全数据**。

即SecurityManager要验证用户的身份时，他需要从Realm中获取相应的数据以确定身份是否合法，有没有权限。**所以我们需要自定义Realm，把数据库的相关数据（角色、权限）传到shiro中，以使shiro可以认证**。

## JWT 令牌
JSON Web Token 是最流行的跨域身份认证解决方案。

和传统的cookie/session 相比，有如下**优点：**
1. 服务器不需要为每个用户保存一块session区域，这就省去了服务器的内存开销。
2. 这种方式可以更好的在分布式应用中使用，session方式在分布式中，你需要考虑每台服务器中的session信息的同步问题。而JWT方式，由于服务器不保存任何会话数据，容易扩展。

JWT的组成：

1. JWT头部
描述JWT元数据的JSON对象。一般如下：
```
{
  "alg": "HS256",
  "typ": "JWT"
}
```
2. 有效载荷<br>
JWT的主体内容部分，需要传递的数据，也是JSON对象。有七个默认字段可以选择，我只用到下面两个，和一个自定义字段。
```
iat : 发布时间
exp ：到期时间
username ： 用户名（自定义字段）
```
3. 签名
JWT的前两部分+一个密钥 经过指定的算法生成。

最后生成的令牌（token） 是一个字符串，三部分之间有`.`分割。

## spring boot 中 使用 Shiro + JWT 的方式进行权限管理
首先说一下实现思想：
1. 用户登录成功后，返回token。
2. 当用户访问接口时，先通过自定义的过滤器进行拦截请求，认证请求头中的token。
3. 如果token合理，则直接委托给shiro的认证模块（但是shiro中就不需要认证了，因为token已经认证通过了，只是是为了让shiro知道该用户的身份）。
4. 当用户访问设置个权限的url时，会访问到shiro的授权模块（即在自定义Realm方法中根据用户名从数据库中得到权限信息，shiro会根据该权限信息与该url的受限权限进行匹配。）

**实例：**
maven依赖：
```xml
    <!--spring boot 整合shiro依赖-->
		<dependency>
			<groupId>org.apache.shiro</groupId>
			<artifactId>shiro-spring</artifactId>
			<version>1.4.0</version>
		</dependency>
		<!--shiro依赖-->
		<dependency>
			<groupId>org.apache.shiro</groupId>
			<artifactId>shiro-all</artifactId>
			<version>1.4.0</version>
		</dependency>
		<!--JWT-->
		<dependency>
			<groupId>com.auth0</groupId>
			<artifactId>java-jwt</artifactId>
			<version>3.4.0</version>
		</dependency>
```
shiro的配置类：
```java
package com.alonge.shirodemo.config;

import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Shiro配置类
 */
@Configuration
public class ShiroConfig {
    /**
     * 设置shiro的过滤器
     * @param securityManager   安全管理器
     * @return  shiro过滤器
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        Map< String, Filter> filterMap = new HashMap<>();
        // filterMap.put("rolesOr", manyRoles());
        // 自定义Token过滤器，加入到shiro过滤器链中
        filterMap.put("jwt", new MyJWTFilter());
        shiroFilterFactoryBean.setFilters(filterMap);
        // 设置SecurityManager
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        // 设置url的拦截器map, 在实际项目中我们使用查数据库的方式，动态配置
        Map< String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        // 不拦截静态资源
        filterChainDefinitionMap.put("/static/**", "anon");
        // 不拦截swagger-ui.html
        filterChainDefinitionMap.put("/swagger-ui.html","anon");
        filterChainDefinitionMap.put("/login","anon");
        // 游客
        filterChainDefinitionMap.put("/guest/**", "anon");
        // 设置退出url
        filterChainDefinitionMap.put("/logout", "logout");
        filterChainDefinitionMap.put("/index", "user");
        // 设置访问、api/admin 接口 所需的角色为admin
        filterChainDefinitionMap.put("/api/admin", "jwt,roles[admin]");
        filterChainDefinitionMap.put("/api/user", "jwt,roles[user]");
        // 拦截其余接口
        filterChainDefinitionMap.put("/**", "jwt");

        // 设置登录页,如果不设置默认寻找/login.jsp
        shiroFilterFactoryBean.setLoginUrl("/login");
        shiroFilterFactoryBean.setUnauthorizedUrl("/notRole");
        shiroFilterFactoryBean.setSuccessUrl("/index");
        shiroFilterFactoryBean.setFilterChainDefinitionMap(filterChainDefinitionMap);
        System.out.println("Shiro拦截器工厂类注入成功");
        return shiroFilterFactoryBean;
    }

    @Bean
    public SecurityManager securityManager(){
        DefaultWebSecurityManager securityManager = new DefaultWebSecurityManager();
        // 设置realm
        securityManager.setRealm(userRealm());
        // 由于我们使用JWT的认证方式，所以我们不需要session，关闭shiro自带的session
        DefaultSubjectDAO subjectDAO = new DefaultSubjectDAO();
        DefaultSessionStorageEvaluator defaultSessionStorageEvaluator = new DefaultSessionStorageEvaluator();
        defaultSessionStorageEvaluator.setSessionStorageEnabled(false);
        subjectDAO.setSessionStorageEvaluator(defaultSessionStorageEvaluator);
        securityManager.setSubjectDAO(subjectDAO);
        return securityManager;
    }

    /**
     * 注入我们自定义的userRealm
     * @return
     */
    @Bean
    public UserRealm userRealm() {
        UserRealm userRealm = new UserRealm();
        // 设置解密规则，使securityManager 可以正确认证密码
      // userRealm.setCredentialsMatcher(hashedCredentialsMatcher());
        return userRealm;
    }

    /**
     * 开启shiro 注解方式支持
     * 使用的是代理方式 Spring AOP
     * @param securityManager
     * @return
     */
    @Bean
    public AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor(SecurityManager securityManager){
        AuthorizationAttributeSourceAdvisor authorizationAttributeSourceAdvisor = new AuthorizationAttributeSourceAdvisor();
        authorizationAttributeSourceAdvisor.setSecurityManager(securityManager);
        return authorizationAttributeSourceAdvisor;
    }
}
```
自定义Realm：
```java
package com.alonge.shirodemo.config;

import com.alonge.shirodemo.domain.Role;
import com.alonge.shirodemo.utils.JwtUtil;
import org.apache.shiro.authc.*;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import java.util.HashSet;
import java.util.Set;

public class UserRealm extends AuthorizingRealm {

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
        // 本案例为了简单，是模拟的角色。实际情况应从数据库中获取
        Role role = getRoleByUsername(username);
        Set< String> roles = new HashSet<>();
        roles.add(role.getRoleName());
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

    /**
     * 模拟用户权限
     * 实际项目从数据库中查询
     */
    private Role getRoleByUsername(String username) {
        if("user".equals(username)) {
            return new Role("user");
        }else if ("admin".equals(username)) {
            return new Role(username);
        }
        return new Role("visitor");
    }
}
```
自定义的Token过滤器：
```java
package com.alonge.shirodemo.config;

import com.alonge.shirodemo.utils.JwtUtil;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.web.filter.authc.BasicHttpAuthenticationFilter;
import org.apache.shiro.web.util.WebUtils;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.RequestMethod;

import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class MyJWTFilter extends BasicHttpAuthenticationFilter {

    /**
     * 是否允许访问
     * 返回true表示允许，返回false标识不允许
     * @param servletRequest
     * @param servletResponse
     * @param o
     * @return
     */
    @Override
    protected boolean isAccessAllowed(ServletRequest servletRequest, ServletResponse servletResponse, Object o) {
        System.out.println("is access allowed");
        return false;
    }

    /**
     * 不允许访问时进行的操作：
     * 此处进行认证token 委托给shiro进行登录,并继续由拦截器链执行
     * 返回false表示自己已经处理了（比如重定向到另一个页面）
     * @param servletRequest
     * @param servletResponse
     * @return
     * @throws Exception
     */
    @Override
    protected boolean onAccessDenied(ServletRequest servletRequest, ServletResponse servletResponse) throws Exception {
        System.out.println("on access denied");
        HttpServletRequest request = WebUtils.toHttp(servletRequest);
        String token = request.getHeader("Authorization");
       if (null != JwtUtil.verifyToken(token)){
           try {
               UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(token, token);
               // 委托realm进行认证
               getSubject(servletRequest, servletResponse).login(usernamePasswordToken);
               return true;
           } catch (Exception e) {
               return false;
           }
       }
        return false;
    }

    /**
     * 对跨域提供支持
     */
    @Override
    protected boolean preHandle(ServletRequest request, ServletResponse response) throws Exception {
        HttpServletRequest httpServletRequest = (HttpServletRequest) request;
        HttpServletResponse httpServletResponse = (HttpServletResponse) response;
        httpServletResponse.setHeader("Access-control-Allow-Origin", httpServletRequest.getHeader("Origin"));
        httpServletResponse.setHeader("Access-Control-Allow-Methods", "GET,POST,OPTIONS,PUT,DELETE");
        httpServletResponse.setHeader("Access-Control-Allow-Headers", httpServletRequest.getHeader("Access-Control-Request-Headers"));
        // 跨域时会首先发送一个option请求，这里我们给option请求直接返回正常状态
        if (httpServletRequest.getMethod().equals(RequestMethod.OPTIONS.name())) {
            httpServletResponse.setStatus(HttpStatus.OK.value());
            return false;
        }
        return super.preHandle(request, response);
    }
}

```
Token生成和认证的工具类：
```java
package com.alonge.shirodemo.utils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.Claim;
import com.auth0.jwt.interfaces.DecodedJWT;

import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

/**
 * @author wuyanlong
 * @desc JWT 工具类
 */
public class JwtUtil {

    /**
     * 签名加密密钥，保存在服务端，是随意定义的
     */
    public static String SECRET = "SDFEEdfdeFDRE";


    public static String createToken(String username) {
        //签发时间
        Date istDate = new Date();

        //设置过期时间
        Calendar nowTime = Calendar.getInstance();
        // token有效时间为5分钟
        nowTime.add(Calendar.MINUTE, 5);
        Date expiresDate = nowTime.getTime();

        Map< String, Object> map = new HashMap<>();
        map.put("alg", "HS256");
        map.put("typ", "JWT");

        String token = "";
        try {
             token = JWT.create()
                    .withHeader(map)
                    .withClaim("username", username)
                    .withExpiresAt(expiresDate)
                    .withIssuedAt(istDate)
                    .sign(Algorithm.HMAC256(SECRET));
        }catch (Exception e) {
            return token;
        }
        return token;
    }


    public static Map< String, Claim> verifyToken(String token){
        JWTVerifier verifier = JWT.require(Algorithm.HMAC256(SECRET)).build();
        DecodedJWT jwt = null;
        try {
            jwt = verifier.verify(token);
        } catch (Exception e) {
            return null;
        }

        return jwt.getClaims();
    }

    public static String getUsername(String token) {
        try {
            DecodedJWT jwt = JWT.decode(token);
            return jwt.getClaim("username").asString();
        } catch (JWTDecodeException e) {
            return null;
        }
    }
}

```
控制层测试接口：
```java
package com.alonge.shirodemo.controller;

import com.alonge.shirodemo.utils.JwtUtil;
import org.springframework.web.bind.annotation.*;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping
public class UserController {
    /**
     * 登录接口, 登录成功返回token
     */
    @PostMapping("/login")
    public Map< String, String> login(@RequestParam Map< String, String> params) {
        Map< String, String> resultMap = new HashMap<>();
        System.out.println("登录接口");
        String username = params.get("username");
        String password = params.get("password");
        if (!checkPassword(username, password)){
            return resultMap;
        }
        // 用户名密码验证成功，则生成token
        String token = JwtUtil.createToken(username);
        if ("".equals(token) || null == token) {
            resultMap.put("message","login fail !!");
        }
        resultMap.put("token",token);
        return resultMap;
    }
    
    /**
     * 不需要任何权限都可以访问的test接口
     */
    @RequestMapping(value = "/api/test", method = RequestMethod.POST)
    public Map< String, String> test(@RequestParam Map< String, String> params) {
        Map< String, String> resultMap = new HashMap<>();
        resultMap.put("messgae", "test接口");
        return resultMap;
    }
    
    /**
     * 需要user角色才能访问的接口
     */
    @ApiOperation(value = "普通用户user访问接口")
    @RequestMapping(value = "/api/user", method = RequestMethod.POST)
    //@RequiresRoles(value = {"user"})
    public Map< String,String> user(@RequestParam Map< String, String> param) {
        Map< String, String> resultMap = new HashMap<>();
        resultMap.put("message", "我是普通用户user");
        System.out.println("我是普通用户user");
        return resultMap;
    }
    
    /**
     * 需要admin角色才能访问的接口
     */
    @ApiOperation(value = "管理员admin访问接口")
    @PostMapping(value = "/api/admin")
    //@RequiresRoles(value = {"admin"})
    public Map< String,String> admin(@RequestParam Map< String, String> param) {
        Map< String, String> resultMap = new HashMap<>();
        resultMap.put("message", "我是管理员admin");
        System.out.println("我是管理员admin");
        return resultMap;
    }
```

