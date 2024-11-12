package com.chensoul;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;


@EnableScheduling
@SpringBootApplication
public class Part04OAuthClientApplication {

    public static void main(String[] args) {
        SpringApplication.run(Part04OAuthClientApplication.class, args);
    }
}
