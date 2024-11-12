package com.chensoul;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;

@Slf4j
@Service
public class WelcomeJob {

    @Autowired
    private WebClient webClient;

    @Scheduled(cron = "0/2 * * * * ? ")
    public void exchange() {
        String result = this.webClient
                .get()
                .uri("http://localhost:8090/")
                .attributes(clientRegistrationId("spring"))
                .retrieve()
                .bodyToMono(String.class)
                .block();
        log.info("Call resource server: " + result);
    }
}
