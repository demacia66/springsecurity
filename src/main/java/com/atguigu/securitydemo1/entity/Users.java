package com.atguigu.securitydemo1.entity;

import lombok.Data;
import lombok.Getter;
@Data//生成对应的get set toString
public class Users {

    private Integer id;
    private String username;
    private String password;
}
