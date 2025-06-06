package com.chensoul.config;

import com.chensoul.support.AccessTokenResponseHandler;
import com.chensoul.support.FederatedIdentityAuthenticationSuccessHandler;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerAutoConfiguration;
import org.springframework.boot.autoconfigure.security.oauth2.server.servlet.OAuth2AuthorizationServerJwtAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.session.SessionRegistry;
import org.springframework.security.core.session.SessionRegistryImpl;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.session.HttpSessionEventPublisher;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;

import java.util.UUID;

import static org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer.authorizationServer;

/**
 * @see OAuth2AuthorizationServerAutoConfiguration
 * @see OAuth2AuthorizationServerJwtAutoConfiguration
 */
@Configuration
public class SecurityConfig {

	private static final String CUSTOM_CONSENT_PAGE_URI = "/oauth2/consent";

	@Bean
	@Order(Ordered.HIGHEST_PRECEDENCE)
	SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
		OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = authorizationServer();

		http.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
			.with(authorizationServerConfigurer,
					(authorizationServer) -> authorizationServer
						.authorizationEndpoint(
								authorizationEndpoint -> authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
						.tokenEndpoint(token -> token.accessTokenResponseHandler(new AccessTokenResponseHandler()))
						.oidc(Customizer.withDefaults()) // Enable OpenID Connect 1.0
			)
			// Redirect to the login page when not authenticated from the
			// authorization endpoint
			.exceptionHandling((exceptions) -> exceptions.defaultAuthenticationEntryPointFor(
					new LoginUrlAuthenticationEntryPoint("/login"), new MediaTypeRequestMatcher(MediaType.TEXT_HTML)));

		return http.build();
	}

	@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests(
				authorize -> authorize.requestMatchers("/webjars/**", "/assets/**", "/login", "/logged-out")
					.permitAll()
					.anyRequest()
					.authenticated())
			.formLogin(formLogin -> formLogin.loginPage("/login"))
			.oauth2Login(oauth2Login -> oauth2Login.loginPage("/login").successHandler(authenticationSuccessHandler()));

		return http.build();
	}

	private AuthenticationSuccessHandler authenticationSuccessHandler() {
		return new FederatedIdentityAuthenticationSuccessHandler();
	}

	// @formatter:off
    @Bean
    public UserDetailsService users() {
        UserDetails user = User.withDefaultPasswordEncoder()
                .username("user")
                .password("password")
                .roles("USER")
                .build();
        return new InMemoryUserDetailsManager(user);
    }

    @Bean
    public RegisteredClientRepository registeredClientRepository() {
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
                .scope("client.create")
                .scope("client.read")
                .build();

        RegisteredClient pkceClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("pkce-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
                .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_POST)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("http://127.0.0.1:4200")
                .redirectUri("https://oidcdebugger.com/debug")
                .redirectUri("https://oauthdebugger.com/debug")
                .redirectUri("http://127.0.0.1:8080/login/oauth2/code/pkce-client")
                .postLogoutRedirectUri("http://127.0.0.1:8080/")
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
		return new InMemoryRegisteredClientRepository(oidcClient, credentialsClient, pkceClient, opaqueClient);
	}

	@Bean
	public AuthorizationServerSettings authorizationServerSettings() {
		return AuthorizationServerSettings.builder().build();
	}

	@Bean
	public OAuth2AuthorizationService authorizationService() {
		return new InMemoryOAuth2AuthorizationService();
	}

	@Bean
	public OAuth2AuthorizationConsentService authorizationConsentService() {
		return new InMemoryOAuth2AuthorizationConsentService();
	}

	@Bean
	public SessionRegistry sessionRegistry() {
		return new SessionRegistryImpl();
	}

	@Bean
	public HttpSessionEventPublisher httpSessionEventPublisher() {
		return new HttpSessionEventPublisher();
	}

}