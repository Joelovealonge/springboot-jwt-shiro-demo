package com.alonge.shirodemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.jdbc.DataSourceAutoConfiguration;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import springfox.documentation.swagger2.annotations.EnableSwagger2;

@SpringBootApplication(exclude = { DataSourceAutoConfiguration.class})
@EnableSwagger2
public class ShiroDemoApplication {
/*	@Bean
	public FilterRegistrationBean registrationBean(MyJWTFilterPlus filterPlus) {
		FilterRegistrationBean registrationBean = new FilterRegistrationBean(filterPlus);
		registrationBean.setEnabled(false);
		return registrationBean;
	}*/

	public static void main(String[] args) {
		SpringApplication.run(ShiroDemoApplication.class, args);
	}
}
