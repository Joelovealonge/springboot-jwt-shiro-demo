package com.alonge.shirodemo.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import springfox.documentation.builders.ApiInfoBuilder;
import springfox.documentation.builders.PathSelectors;
import springfox.documentation.builders.RequestHandlerSelectors;
import springfox.documentation.service.ApiInfo;
import springfox.documentation.spi.DocumentationType;
import springfox.documentation.spring.web.plugins.Docket;

@Configuration
public class SwaggerUIConfig {

    @Bean
    public Docket cretaeRestApi() {
        System.out.println("swagger 构建成功");
        return new Docket(DocumentationType.SWAGGER_2)
                .apiInfo(apiInfo())
                .select()
                .apis(RequestHandlerSelectors.basePackage("com.alonge.shirodemo"))
                .paths(PathSelectors.any())
                .build();
    }

    // 构建api 文档的详细信息函数
    private ApiInfo apiInfo() {
        return new ApiInfoBuilder()
                // 页面标题
                .title("项目测试使用Swagger2构建RESTful API")
                // 版本
                .version("1.0")
                // 描述
                .description("API描述")
                .build();
    }
}
