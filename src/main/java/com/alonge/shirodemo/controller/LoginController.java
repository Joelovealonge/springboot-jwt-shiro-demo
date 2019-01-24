package com.alonge.shirodemo.controller;

import com.alonge.shirodemo.utils.JwtUtil;
import com.alonge.shirodemo.utils.Result;
import com.alonge.shirodemo.utils.ResultCodeEnum;
import com.alonge.shirodemo.utils.SucessResult;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import io.swagger.annotations.ApiParam;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.annotation.Logical;
import org.apache.shiro.authz.annotation.RequiresRoles;
import org.apache.shiro.mgt.DefaultSubjectFactory;
import org.apache.shiro.mgt.RealmSecurityManager;
import org.apache.shiro.mgt.SubjectFactory;
import org.apache.shiro.session.Session;
import org.apache.shiro.subject.Subject;
import org.apache.shiro.subject.support.DelegatingSubject;
import org.apache.shiro.web.mgt.DefaultWebSecurityManager;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@Api(value = "控制层")
@RequestMapping
//@RequiresRoles(value = {"user"})
public class LoginController {

    @PostMapping("/login")
    public Result login(@RequestParam Map<String, String> params) {

        System.out.println("登录接口");
        String username = params.get("username");
        String password = params.get("password");
        if (!checkPassword(username, password)){ ;
            return new Result(ResultCodeEnum.ERROR_USERNAME_PASSWORD,
                    "");
        }
        String token = JwtUtil.createToken(username);
        /*UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(token, token);
        Subject subject = SecurityUtils.getSubject();
        try {
            subject.login(usernamePasswordToken);
        } catch (Exception e){
            resultMap.put("message","login fail !!");
        }*/

        return new Result(ResultCodeEnum.SUCCESS,
                token);
    }

    @RequestMapping(value = "/api/test", method = RequestMethod.POST)
    public Result test() {
        return new Result(ResultCodeEnum.SUCCESS, "这是test接口，所有人都可以访问");
    }

    @ApiOperation(value = "游客访问接口")
    @PostMapping(value = "/guest/visitor")
    //@RequiresRoles(value = {"admin", "user", "visitor"}, logical = Logical.OR)
    public Map<String,String> visitor(@RequestParam Map<String, String> param) {
        Map<String, String> resultMap = new HashMap<>();
        resultMap.put("message", "我是游客visitor");
        System.out.println("我是游客visitor");
        return resultMap;
    }

    @ApiOperation(value = "普通用户user访问接口")
    @RequestMapping(value = "/api/user", method = RequestMethod.POST)
    //@RequiresRoles(value = {"user"})
    public Result user() {
        return new Result(ResultCodeEnum.SUCCESS, "这是user接口，只有拥有角色user才可以访问");
    }
    @ApiOperation(value = "管理员admin访问接口")
    @PostMapping(value = "/api/admin")
    //@RequiresRoles(value = {"admin"})
    public Result admin() {
        return new Result(ResultCodeEnum.SUCCESS, "这是admin接口，只有拥有角色admin才可以访问");
    }

    /**
     * token错误是的返回
     * @return
     */
    @RequestMapping(value = "/tokenError")
    public Result tokenError(){
        Result result = new Result(ResultCodeEnum.ERROR_TOKEN.getCode(),
                ResultCodeEnum.ERROR_TOKEN.getMessage());
        return result;
    }

    /**
     * 没有权限时返回
     * @return
     */
    @RequestMapping(value = "/notRole", method = RequestMethod.GET)
    public Result notRole() {
        Result result = new Result(ResultCodeEnum.ERROR_PERMISSION.getCode(),
                ResultCodeEnum.ERROR_PERMISSION.getMessage());
        return result;
    }

    @RequestMapping(value = "/logout", method = RequestMethod.GET)
    public Map<String, String> logout() {
        Map<String, String> resultMap = new HashMap<>();
        Subject subject = SecurityUtils.getSubject();
        subject.logout();
        resultMap.put("message", "注销成功");
        return resultMap;
    }

    private boolean checkPassword(String username, String password) {
        if (("user".equals(username) && "user".equals(password))
                || ("admin".equals(username) && "admin".equals(password))) {
            return true;
        }
        return false;
    }

    /* @ApiOperation(value = "登录接口")
    @PostMapping(value = "/login")
    public Map<String, String> login(@RequestParam Map<String, String> param) {

        Map<String, String> resultMap = new HashMap<>();
        // 认证提交之前准备token(令牌)
        UsernamePasswordToken token = new UsernamePasswordToken(param.get("username"), param.get("password"));
        // 创建一个subject对象
        Subject subject = SecurityUtils.getSubject();
        try{
            if (!subject.isAuthenticated()) {
                // 执行认证
                subject.login(token);
                System.out.println("login认证");
                resultMap.put("token", JwtUtil.sign(param.get("username"), "secret"));
            }else {
                System.out.println("已经认证过了");
                resultMap.put("message","已经认证过了");
            }

        }catch (Exception e){
            resultMap.put("message","认证失败");
        }

        //resultMap.put("message", "登录成功");
        return resultMap;
    }*/
}
