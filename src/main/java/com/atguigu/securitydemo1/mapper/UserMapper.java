package com.atguigu.securitydemo1.mapper;

import com.atguigu.securitydemo1.entity.Users;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import org.springframework.stereotype.Repository;

@Repository//不加会报错
public interface UserMapper extends BaseMapper<Users> {
}
