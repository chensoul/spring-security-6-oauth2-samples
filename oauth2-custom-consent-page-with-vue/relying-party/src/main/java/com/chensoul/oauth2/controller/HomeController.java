package com.chensoul.oauth2.controller;

import java.util.Collections;
import java.util.Map;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;


@RestController
public class HomeController {

    @GetMapping("/home")
    public Map<String, String> home(Authentication authentication) {
        return Collections.singletonMap("name", authentication.getName());
    }
}
