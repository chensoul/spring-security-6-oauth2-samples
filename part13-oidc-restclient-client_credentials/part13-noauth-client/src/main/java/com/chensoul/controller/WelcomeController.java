package com.chensoul.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.server.ResponseStatusException;

@Slf4j
@RestController
public class WelcomeController {
    private final RestClient restClient;

    public WelcomeController(RestClient.Builder builder) {
        this.restClient = builder
                .baseUrl("http://localhost:8081")
                .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                .defaultStatusHandler(HttpStatusCode::is4xxClientError, (request, response) -> {
                    if (response.getStatusCode()==HttpStatus.UNAUTHORIZED) {
                        throw new ResponseStatusException(HttpStatus.UNAUTHORIZED, "Unauthorized access to lessons API");
                    }
                    throw new ResponseStatusException(response.getStatusCode(), "Client error occurred");
                })
                .defaultStatusHandler(HttpStatusCode::is5xxServerError, (request, response) -> {
                    throw new ResponseStatusException(HttpStatus.SERVICE_UNAVAILABLE,
                            "Downstream service error: " + response.getStatusCode());
                })
                .build();
    }

    @GetMapping("/")
    public String welcome() {
        String result = restClient.get()
                .uri("http://localhost:8090")
                .retrieve()
                .body(String.class);
        return "<h1>" + result + "</h1>";
    }

}