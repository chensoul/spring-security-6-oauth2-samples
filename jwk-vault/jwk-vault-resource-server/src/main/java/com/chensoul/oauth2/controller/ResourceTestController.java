package com.chensoul.oauth2.controller;

import java.util.Collections;
import java.util.Map;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class ResourceTestController {

    @GetMapping("/resource/test")
    public Map<String, Object> getArticles(@AuthenticationPrincipal Jwt jwt) {
        return Collections.singletonMap("Resource Server", jwt.getClaims());
    }
}
