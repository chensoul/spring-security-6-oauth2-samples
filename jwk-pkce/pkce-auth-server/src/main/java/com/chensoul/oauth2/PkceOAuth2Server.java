package com.chensoul.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;


@SpringBootApplication
public class PkceOAuth2Server {

    public static void main(String[] args) {
        SpringApplication.run(PkceOAuth2Server.class, args);
    }
}
