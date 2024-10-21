package com.chensoul.oauth2.config;

import com.chensoul.oauth2.jwt.VaultJwtDecoder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.vault.core.VaultTemplate;


@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http.authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/resource/test/**").hasAuthority("SCOPE_message.read"))
                .oauth2ResourceServer()
                .jwt();
        return http.build();
    }

    @Bean
    JwtDecoder jwtDecoder(VaultTemplate vaultTemplate) {
        return new VaultJwtDecoder(vaultTemplate);
    }
}
