package com.chensoul.controller;

import com.chensoul.config.WelcomeClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;

@RestController
@RequiredArgsConstructor
public class WelcomeController {
    private final WelcomeClient welcomeClient;

    @GetMapping("/")
    public String welcome() {
        String welcome = welcomeClient.getWelcome();
        return "<h1>" + welcome + "</h1>";
    }

}