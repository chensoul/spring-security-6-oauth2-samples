package com.chensoul.config;

import java.time.Duration;
import java.util.UUID;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

@Configuration
public class ClientConfig {

    @Bean
    public RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
        return new JdbcRegisteredClientRepository(jdbcTemplate);
    }

    @Bean
    ApplicationRunner clientsRunner(RegisteredClientRepository repository) {
        return args -> {
            RegisteredClient clientCredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("clientCredClient")
                    .clientSecret("{noop}clientCredClient")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("read")
                    .scope("write")
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofDays(10))
                            .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                            .build()
                    ).build();

            RegisteredClient introspectClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("introspectClient")
                    .clientSecret("{noop}introspectClient")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("read")
                    .scope("write")
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofDays(10))
                            .accessTokenFormat(OAuth2TokenFormat.REFERENCE)
                            .build()
                    ).build();

            RegisteredClient authCodeClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("authCodeClient")
                    .clientSecret("{noop}authCodeClient")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("https://oidcdebugger.com/debug")
                    .redirectUri("https://oauthdebugger.com/debug")
                    .redirectUri("http://127.0.0.1:8080/login/oauth2/code/authCodeClient")
                    .redirectUri("http://127.0.0.1:8080/authorized")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("read")
                    .scope("write")
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofDays(10))
                            .refreshTokenTimeToLive(Duration.ofDays(20))
                            .reuseRefreshTokens(false)
                            .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build()
                    ).build();

            RegisteredClient pkceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("pkceClient")
                    .clientSecret("{noop}pkceClient")
                    .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                    .redirectUri("https://oidcdebugger.com/debug")
                    .redirectUri("https://oauthdebugger.com/debug")
                    .redirectUri("http://127.0.0.1:8080/login/oauth2/code/authCodeClient")
                    .redirectUri("http://127.0.0.1:8080/authorized")
                    .scope(OidcScopes.OPENID)
                    .scope(OidcScopes.PROFILE)
                    .scope("read")
                    .scope("write")
                    .clientSettings(ClientSettings.builder()
                            .requireProofKey(true)
                            .requireAuthorizationConsent(true)
                            .build()
                    )
                    .tokenSettings(TokenSettings.builder()
                            .accessTokenTimeToLive(Duration.ofDays(10))
                            .refreshTokenTimeToLive(Duration.ofDays(20))
                            .reuseRefreshTokens(false)
                            .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED).build()
                    ).build();

            if (repository.findByClientId(clientCredClient.getClientId())==null) {
                repository.save(clientCredClient);
            }
            if (repository.findByClientId(introspectClient.getClientId())==null) {
                repository.save(introspectClient);
            }
            if (repository.findByClientId(authCodeClient.getClientId())==null) {
                repository.save(authCodeClient);
            }
            if (repository.findByClientId(pkceClient.getClientId())==null) {
                repository.save(pkceClient);
            }

        };
    }
}