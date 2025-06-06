package com.chensoul.config;

import com.chensoul.domain.Authority;
import com.chensoul.domain.AuthorityRepository;
import com.chensoul.domain.User;
import com.chensoul.domain.UserRepository;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;

import java.util.UUID;

/**
 * @see OAuth2AuthorizationServerAutoConfiguration
 */
@EnableWebSecurity
@Configuration
public class SecurityConfig {

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

            RegisteredClient pkceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                    .clientId("pkce-client")
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
			if (repository.findByClientId(pkceClient.getClientId()) == null) {
				repository.save(pkceClient);
			}
		};
	}

	@Bean
	ApplicationRunner usersRunner(UserRepository userRepository, AuthorityRepository authorityRepository) {
		return args -> {
			userRepository.save(new User("user", "{noop}password"));
			authorityRepository.save(new Authority("user", "USER"));
		};
	}

}