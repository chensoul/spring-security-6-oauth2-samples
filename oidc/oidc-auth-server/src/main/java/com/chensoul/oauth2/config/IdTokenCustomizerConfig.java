package com.chensoul.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

import java.util.stream.Collectors;

/**
 * Custom IdToken
 *
 *
 *
 */
@Configuration(proxyBeanMethods = false)
public class IdTokenCustomizerConfig {

    /**
     * IdToken add role claim
     *
     * @return
     */
    @Bean
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer() {
        return (context) -> {
            if (OidcParameterNames.ID_TOKEN.equals(context.getTokenType().getValue())) {
                context.getClaims().claims(claims ->
                        claims.put("role", context.getPrincipal().getAuthorities()
                                .stream().map(GrantedAuthority::getAuthority)
                                .collect(Collectors.toSet())));
            }
        };
    }
}
