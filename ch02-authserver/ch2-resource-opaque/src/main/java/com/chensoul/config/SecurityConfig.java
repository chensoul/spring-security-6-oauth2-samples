package com.chensoul.config;

import java.time.Duration;
import java.util.ArrayList;
import java.util.Collection;
import java.util.stream.Collectors;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.autoconfigure.security.oauth2.resource.OAuth2ResourceServerProperties;
import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.boot.web.client.RestTemplateBuilder;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.oauth2.server.resource.introspection.SpringOpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.client.RestOperations;

/**
 * @see OAuth2ResourceServerAutoConfiguration
 */
@RequiredArgsConstructor
@EnableWebSecurity
@Configuration
public class SecurityConfig {
    private final OAuth2ResourceServerProperties properties;

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .authorizeHttpRequests((authorize) -> authorize
                        .requestMatchers(HttpMethod.GET, "/message/**").hasAuthority("SCOPE_read")
                        .requestMatchers(HttpMethod.POST, "/message/**").hasAuthority("SCOPE_write")
                        .anyRequest().authenticated()
                )
                .oauth2ResourceServer(rsc ->
                        rsc.opaqueToken(otc -> otc
                                .introspectionUri(properties.getOpaquetoken().getIntrospectionUri())
                                .introspectionClientCredentials(properties.getOpaquetoken().getClientId(), properties.getOpaquetoken().getClientSecret())
                        ));

        return http.build();
    }

    @Bean
    public OpaqueTokenIntrospector introspector(RestTemplateBuilder builder, OAuth2ResourceServerProperties properties) {
        RestOperations rest = builder
                .basicAuthentication(properties.getOpaquetoken().getClientId(), properties.getOpaquetoken().getClientSecret())
                .connectTimeout(Duration.ofSeconds(60))
                .readTimeout(Duration.ofSeconds(60))
                .build();

        return new SpringOpaqueTokenIntrospector(properties.getOpaquetoken().getIntrospectionUri(), rest);
    }

    public class CustomOpaqueRoleConverter implements OpaqueTokenAuthenticationConverter {
        @Override
        public Authentication convert(String introspectedToken, OAuth2AuthenticatedPrincipal authenticatedPrincipal) {
            ArrayList<String> scopes = authenticatedPrincipal.getAttribute("scope");

            // 和 JwtGrantedAuthoritiesConverter 逻辑保持一致
            Collection<GrantedAuthority> grantedAuthorities = scopes
                    .stream().map(roleName -> "SCOPE_" + roleName)
                    .map(SimpleGrantedAuthority::new)
                    .collect(Collectors.toList());
            return new UsernamePasswordAuthenticationToken(authenticatedPrincipal.getName(), null,
                    grantedAuthorities);
        }
    }
}