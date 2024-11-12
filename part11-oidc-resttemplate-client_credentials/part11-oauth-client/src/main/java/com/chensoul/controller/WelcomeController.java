package com.chensoul.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import lombok.RequiredArgsConstructor;
import org.springframework.web.client.RestTemplate;

@Slf4j
@RestController
@RequiredArgsConstructor
public class WelcomeController {
    @Autowired
    RestTemplateBuilder restTemplateBuilder;

    @GetMapping("/")
    public String welcome() {
        RestTemplate restTemplate = restTemplateBuilder.build();
        String result = restTemplate.getForEntity("http://localhost:8090/", String.class).getBody();
        return "<h1>" + result + "</h1>";
    }

}