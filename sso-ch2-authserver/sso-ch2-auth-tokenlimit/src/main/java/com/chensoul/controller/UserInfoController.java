package com.chensoul.controller;

import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class UserInfoController {

    @PostMapping("/userinfo")
    public Map<String, Object> getUserInfo(@AuthenticationPrincipal Jwt jwt) {
        return jwt.getClaims();
    }
}