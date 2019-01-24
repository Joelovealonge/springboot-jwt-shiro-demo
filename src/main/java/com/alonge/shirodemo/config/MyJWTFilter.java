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
import java.io.IOException;

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
        try {
            if (null != JwtUtil.verifyToken(token)) {

                UsernamePasswordToken usernamePasswordToken = new UsernamePasswordToken(token, token);
                // 委托realm进行认证
                getSubject(servletRequest, servletResponse).login(usernamePasswordToken);
                return true;
            }
        } catch (Exception e){
            responseError(servletResponse, "/tokenError");
            return false;
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

    /**
     * 将非法请求跳转到 /unauthorized/**
     */
    private void responseError(ServletResponse response, String url) {
        try {
            HttpServletResponse httpServletResponse = (HttpServletResponse) response;
            //设置编码，否则中文字符在重定向时会变为空字符串
            //message = URLEncoder.encode(message, "UTF-8");
            httpServletResponse.sendRedirect(url);
        } catch (IOException e) {
            System.out.println(e.getMessage());
        }
    }
}
