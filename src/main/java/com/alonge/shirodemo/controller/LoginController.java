package com.alonge.shirodemo.controller;

import com.alonge.shirodemo.service.UserService;
import com.alonge.shirodemo.utils.JwtUtil;
import com.alonge.shirodemo.utils.Result;
import com.alonge.shirodemo.utils.ResultCodeEnum;
import io.swagger.annotations.Api;
import io.swagger.annotations.ApiOperation;
import org.apache.shiro.SecurityUtils;
import org.apache.shiro.subject.Subject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@RestController
@Api(value = "控制层")
@RequestMapping
//@RequiresRoles(value = {"user"})
public class LoginController {
    @Autowired
    private UserService userService;

    @PostMapping("/login")
    public Result login(@RequestParam Map<String, String> params) {

        // 帐号或密码错误
        if (!userService.login(params)) {
            return new Result(ResultCodeEnum.ERROR_USERNAME_PASSWORD,
                    "");
        }

        String token = JwtUtil.createToken(params.get("username"));
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
    @RequestMapping(value = "/tokenError", method = RequestMethod.GET)
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

}
