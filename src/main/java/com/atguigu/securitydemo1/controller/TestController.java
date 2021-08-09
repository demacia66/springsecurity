package com.atguigu.securitydemo1.controller;

import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping(value = "/test")
public class TestController {

    @GetMapping(value = "hello")
    public String add(){
        return "hello world";
    }

    @GetMapping(value = "index")
    public String index(){
        return "hello index";
    }

    @GetMapping("update")
//    @Secured({"ROLE_sale","ROLE_manager"})
//    @PreAuthorize("hasAnyAuthority('admins')")
    @PostAuthorize("hasAnyAuthority('admins')")
    public String update(){
        System.out.println("hello");
        return "hello update";
    }
}
