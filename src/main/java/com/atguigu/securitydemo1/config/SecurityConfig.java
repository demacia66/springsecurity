package com.atguigu.securitydemo1.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

//@Configuration
public class SecurityConfig extends WebSecurityConfigurerAdapter {

    //可以设置用户名和密码
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        //用于加密
        BCryptPasswordEncoder passwordEncoder = new BCryptPasswordEncoder();
        //进行加密
        String password = passwordEncoder.encode("123");
        //用户名，密码，角色
        auth.inMemoryAuthentication().withUser("lucy").password(password).roles("admin");
    }

    @Bean
    PasswordEncoder password(){
        return new BCryptPasswordEncoder();
    }
}
