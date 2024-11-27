

package com.chensoul.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import static org.springframework.security.oauth2.client.web.client.RequestAttributeClientRegistrationIdResolver.clientRegistrationId;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.reactive.function.client.WebClient;

@RestController
@Slf4j
public class WelcomeController {
    @Autowired
    private WebClient webClient;

    @GetMapping("/")
    @Scheduled(cron = "0/2 * * * * ? ")
    public String welcome() {
        String result = this.webClient
                .get()
                .uri("http://localhost:8090/")
                .attributes(clientRegistrationId("spring"))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        log.info("Call resource server: " + result);

        return "<h1>" + result + "</h1>";
    }
}