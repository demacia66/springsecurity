package com.atguigu.securitydemo1.service;

import com.atguigu.securitydemo1.entity.Users;
import com.atguigu.securitydemo1.mapper.UserMapper;
import com.baomidou.mybatisplus.core.conditions.query.QueryWrapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.stereotype.Service;

import java.util.List;

@Service("userDetailsService")
public class MyUserDetailsService implements UserDetailsService {



    @Autowired
    private UserMapper userMapper;

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {

        //调用userMapper方法调用数据库,根据用户名查询数据库
        //查询构造器
        QueryWrapper<Users> wrapper = new QueryWrapper<>();
        // where username=?
        wrapper.eq("username",username);

        Users users = userMapper.selectOne(wrapper);
        //判断
        if (users == null){
            //数据库中没有用户名，认证失败
            throw new UsernameNotFoundException("用户名不存在！");
        }

        List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("role");
        //从数据库中返回Users对象，得到用户名密码，返回
        return new User(users.getUsername(), new BCryptPasswordEncoder().encode(users.getPassword()), auths);

//        List<GrantedAuthority> auths = AuthorityUtils.commaSeparatedStringToAuthorityList("role");
//        //权限不能写空
//        return new User("mary", new BCryptPasswordEncoder().encode("123"), auths);
    }
}
