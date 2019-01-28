package com.alonge.shirodemo.config;

import com.alonge.shirodemo.domain.UrlFilter;
import com.alonge.shirodemo.service.UrlFilterService;
import org.apache.shiro.authc.credential.HashedCredentialsMatcher;
import org.apache.shiro.mgt.DefaultSessionStorageEvaluator;
import org.apache.shiro.mgt.DefaultSubjectDAO;
import org.apache.shiro.mgt.SecurityManager;
import org.apache.shiro.spring.security.interceptor.AuthorizationAttributeSourceAdvisor;
import org.apache.shiro.spring.web.ShiroFilterFactoryBean;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.Filter;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Shiro配置类
 */
@Configuration
public class ShiroConfig {

    @Autowired
    UrlFilterService urlFilterService;
    /**
     * 设置shiro的过滤器
     * @param securityManager   安全管理器
     * @return  shiro过滤器
     */
    @Bean
    public ShiroFilterFactoryBean shiroFilter(SecurityManager securityManager) {
        ShiroFilterFactoryBean shiroFilterFactoryBean = new ShiroFilterFactoryBean();
        Map<String, Filter> filterMap = new HashMap<>();
        // filterMap.put("rolesOr", manyRoles());
        // 自定义Token过滤器，加入到shiro过滤器链中
       // filterMap.put("tokenError", new TokenErrorFilter());
        filterMap.put("jwt", new MyJWTFilter());
        shiroFilterFactoryBean.setFilters(filterMap);
        // 设置SecurityManager
        shiroFilterFactoryBean.setSecurityManager(securityManager);

        // 设置url的拦截器map
        Map<String, String> filterChainDefinitionMap = new LinkedHashMap<>();
        List<UrlFilter> urlFilters = urlFilterService.getListFilters();
        for (UrlFilter urlFilter: urlFilters) {
            filterChainDefinitionMap.put(urlFilter.getUrl(), urlFilter.getFilter());
        }

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

    /**
     * 密码匹配规则
     * 我们使用JWT方式，在这儿我们没有用到
     * @return
     */
    @Bean
    public HashedCredentialsMatcher hashedCredentialsMatcher() {
        HashedCredentialsMatcher hashedCredentialsMatcher = new HashedCredentialsMatcher();
        // 散列算法，我们使用md5
        hashedCredentialsMatcher.setHashAlgorithmName("MD5");
        // 散列次数
        hashedCredentialsMatcher.setHashIterations(2);
        return hashedCredentialsMatcher;
    }

}
