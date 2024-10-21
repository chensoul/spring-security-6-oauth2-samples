package com.chensoul.oauth2.configure;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;


@Configuration(proxyBeanMethods = false)
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .requestMatchers("/resource/article").hasAuthority("SCOPE_message.read")
                        .anyRequest().authenticated()
                )
                .apply(new OAuth2IntrospectiveResourceServerAuthorizationConfigurer())
                .opaqueTokenIntrospectorSupport();
        return http.build();
    }
}
