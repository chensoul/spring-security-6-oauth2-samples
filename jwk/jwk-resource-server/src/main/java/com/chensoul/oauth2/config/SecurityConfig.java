package com.chensoul.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
public class SecurityConfig {

  @Bean
  SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
    http.authorizeHttpRequests(authorize -> authorize
                    .requestMatchers("/resource/article").hasAuthority("SCOPE_message.read")
                    .anyRequest().authenticated())
            .oauth2ResourceServer(server -> server.jwt(Customizer.withDefaults()));
    return http.build();
  }
}
