package com.chensoul.controller;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import static org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver.clientRegistrationId;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;

@Slf4j
@RestController
@RequiredArgsConstructor
public class WelcomeController {
    private final RestClient restClient;

    @GetMapping("/")
    public String welcome() {
        String result = restClient.get()
                .uri("http://localhost:8090")
                .attributes(clientRegistrationId("spring"))
                .retrieve()
                .body(String.class);
        return "<h1>" + result + "</h1>";
    }

}