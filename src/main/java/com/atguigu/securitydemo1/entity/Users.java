package com.atguigu.securitydemo1.entity;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Data//生成对应的get set toString
@AllArgsConstructor
@NoArgsConstructor
public class Users {

    private Integer id;
    private String username;
    private String password;
}
