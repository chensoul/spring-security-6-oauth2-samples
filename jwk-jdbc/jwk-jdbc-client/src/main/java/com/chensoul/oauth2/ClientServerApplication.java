package com.chensoul.oauth2;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableScheduling;

@EnableScheduling
@SpringBootApplication
public class ClientServerApplication {

  public static void main(String[] args) {
    SpringApplication.run(ClientServerApplication.class, args);
  }
}
