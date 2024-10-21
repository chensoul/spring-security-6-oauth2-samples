package com.chensoul.oauth2.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;


@Controller
public class LoginSuccessController {

    @GetMapping("/success")
    public String success() {
        return "success";
    }
}
