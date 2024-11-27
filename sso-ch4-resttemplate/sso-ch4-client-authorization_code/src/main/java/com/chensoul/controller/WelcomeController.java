package com.chensoul.controller;

import lombok.RequiredArgsConstructor;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@RestController
@RequiredArgsConstructor
public class WelcomeController {
    final RestTemplateBuilder restTemplateBuilderConfigured;

    @GetMapping("/")
    public String welcome() {
        RestTemplate restTemplate = restTemplateBuilderConfigured.build();
        String welcome = restTemplate.getForEntity("/", String.class).getBody();
        return "<h1>" + welcome + "</h1>";
    }

}