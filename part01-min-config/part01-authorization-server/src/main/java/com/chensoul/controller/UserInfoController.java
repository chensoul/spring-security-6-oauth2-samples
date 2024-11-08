package com.chensoul.controller;

import java.security.Principal;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Collections;
import java.util.Map;

@RestController
public class UserInfoController {

    @PostMapping("/userinfo")
    public Map<String, Object> getUserInfo(@AuthenticationPrincipal Jwt jwt) {
        return Collections.singletonMap("data", jwt.getClaims());
    }
}