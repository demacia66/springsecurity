package com.atguigu.securitydemo1.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;

/**
 * @author yuanchenyu
 */
@Configuration
public class SecurityConfigTest extends WebSecurityConfigurerAdapter {

    @Autowired
    private UserDetailsService userDetailsService;


    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService).passwordEncoder(password());
    }

    @Bean
    PasswordEncoder password() {
        return new BCryptPasswordEncoder();
    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {

        //在配置类配置没有权限访问跳转自定义页面
        http.exceptionHandling().accessDeniedPage("/unauth.html");



        http.formLogin() //自定义自己编写的登陆页面
                .loginPage("/login.html")//登陆页面设置
                .loginProcessingUrl("/user/login")//登陆访问路径
                .defaultSuccessUrl("/test/index").permitAll()//登陆成功跳转
                .and().authorizeRequests()//那些需要认证
//        .antMatchers("/","/test/hello","/user/login").permitAll()//那些路径可以直接访问，不需要认证
                //当前登陆用户，只有具有admins权限才可以访问这个路径
//        .antMatchers("/test/index").hasAuthority("admins")
                //admins和manager都可以访问
//                .antMatchers("/test/index").hasAnyAuthority("admins,manager")

                //3 hasRole方法
                //ROLE_sale
                .antMatchers("/test/index").hasRole("sale")
                .anyRequest().authenticated()//所有请求都可以访问
                .and().csrf().disable();//关闭csrf防护
    }
}
