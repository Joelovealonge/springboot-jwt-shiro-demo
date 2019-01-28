package com.alonge.shirodemo;

import org.mybatis.spring.annotation.MapperScan;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@SpringBootApplication()
@MapperScan(basePackages = "com.alonge.shirodemo.mapper")
@EnableSwagger2
public class ShiroDemoApplication {
	public static void main(String[] args) {
		SpringApplication.run(ShiroDemoApplication.class, args);
	}
}
