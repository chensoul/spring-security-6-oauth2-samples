package com.chensoul;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;


@EnableScheduling
@SpringBootApplication
public class Part09OAuthClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(Part09OAuthClientApplication.class, args);
    }
}
