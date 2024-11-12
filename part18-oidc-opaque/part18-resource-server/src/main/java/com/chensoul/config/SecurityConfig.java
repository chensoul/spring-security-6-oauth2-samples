package com.chensoul.config;

import java.time.Duration;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.oauth2.server.resource.introspection.NimbusOpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestOperations;

@Configuration
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests(authorizeRequests -> authorizeRequests
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(server -> server.opaqueToken(Customizer.withDefaults()));
        return http.build();
    }

    /**
     * The resource server sets a connection and read timeout of 60 seconds to coordinate with the authorization server.
     *
     * @param builder
     * @param properties
     * @return
     */
    @Bean
    public OpaqueTokenIntrospector introspector(RestTemplateBuilder builder, OAuth2ResourceServerProperties properties) {
        RestOperations rest = builder
                .basicAuthentication(properties.getOpaquetoken().getClientId(), properties.getOpaquetoken().getClientSecret())
                .setConnectTimeout(Duration.ofSeconds(60))
                .setReadTimeout(Duration.ofSeconds(60))
                .build();

        return new NimbusOpaqueTokenIntrospector(properties.getOpaquetoken().getIntrospectionUri(), rest);
    }
}