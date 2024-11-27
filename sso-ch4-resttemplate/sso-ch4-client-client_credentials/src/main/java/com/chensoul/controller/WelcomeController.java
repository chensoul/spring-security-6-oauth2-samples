package com.chensoul.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

@Slf4j
@RestController
public class WelcomeController {
    private RestTemplateBuilder restTemplateBuilder;

    @GetMapping("/")
    public String welcome() {
        RestTemplate restTemplate = restTemplateBuilder.build();
        String result = restTemplate.getForEntity("http://localhost:8090/", String.class).getBody();
        return "<h1>" + result + "</h1>";
    }

}