package com.chensoul.config;

import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.util.UUID;

@Configuration
public class ClientConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    ApplicationRunner clientsRunner(RegisteredClientRepository repository) {
        return args -> {
            // @formatter:off
            RegisteredClient oidcClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("oidc-client")
                    .clientSecret("{noop}oidc-client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("https://oidcdebugger.com/debug")
                    .redirectUri("https://oauthdebugger.com/debug")
                    .redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
                    .postLogoutRedirectUri("http://127.0.0.1:8080/")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.ADDRESS)
                    .scope(OidcScopes.EMAIL)
                    .scope(OidcScopes.PHONE)
                    .scope(OidcScopes.PROFILE)
                    .scope("read")
                    .scope("write")
                    .clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
                    .build();

            RegisteredClient credentialsClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("credentials-client")
                    .clientSecret("{noop}credentials-client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("read")
                    .scope("write")
                    .build();

            RegisteredClient publicClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("public-client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .redirectUri("http://127.0.0.1:4200")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .clientSettings(ClientSettings.builder()
                            .requireAuthorizationConsent(true)
                            .requireProofKey(true)
                            .build()
                    )
                    .build();

            RegisteredClient opaqueClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("opaque-client")
                    .clientSecret("{noop}opaque-client")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .tokenSettings(TokenSettings.builder().accessTokenFormat(OAuth2TokenFormat.REFERENCE).build()
                    ).build();

            // @formatter:on

            if (repository.findByClientId(oidcClient.getClientId()) == null) {
                repository.save(oidcClient);
            }
            if (repository.findByClientId(credentialsClient.getClientId()) == null) {
                repository.save(credentialsClient);
            }
            if (repository.findByClientId(opaqueClient.getClientId()) == null) {
                repository.save(opaqueClient);
            }
            if (repository.findByClientId(publicClient.getClientId()) == null) {
                repository.save(publicClient);
            }
        };
    }
}