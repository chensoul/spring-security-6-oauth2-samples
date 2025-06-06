package com.chensoul;

import com.chensoul.domain.JpaOAuth2AuthorizationConsentService;
import com.chensoul.domain.JpaOAuth2AuthorizationService;
import com.chensoul.domain.JpaRegisteredClientRepository;
import com.chensoul.test.AuthorizationCodeGrantFlow;
import com.chensoul.test.DeviceAuthorizationGrantFlow;
import com.chensoul.test.jose.TestJwks;
import com.chensoul.test.junit.SpringTestContext;
import com.chensoul.test.junit.SpringTestContextExtension;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.assertj.core.api.ObjectAssert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.http.MediaType;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.util.matcher.MediaTypeRequestMatcher;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.StringUtils;

import java.util.Map;

import static com.chensoul.test.RegisteredClients.messagingClient;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for the guide How-to: Implement core services with JPA.
 *
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension.class)
public class JpaTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private MockMvc mockMvc;

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Autowired
	private OAuth2AuthorizationService authorizationService;

	@Autowired
	private OAuth2AuthorizationConsentService authorizationConsentService;

	@Test
	public void oidcLoginWhenJpaCoreServicesAutowiredThenUsed() throws Exception {
		this.spring.register(AuthorizationServerConfig.class).autowire();
		assertThat(this.registeredClientRepository).isInstanceOf(JpaRegisteredClientRepository.class);
		assertThat(this.authorizationService).isInstanceOf(JpaOAuth2AuthorizationService.class);
		assertThat(this.authorizationConsentService).isInstanceOf(JpaOAuth2AuthorizationConsentService.class);

		RegisteredClient registeredClient = messagingClient();
		this.registeredClientRepository.save(registeredClient);

		AuthorizationCodeGrantFlow authorizationCodeGrantFlow = new AuthorizationCodeGrantFlow(this.mockMvc);
		authorizationCodeGrantFlow.setUsername("user");
		authorizationCodeGrantFlow.addScope("message.read");
		authorizationCodeGrantFlow.addScope("message.write");

		String state = authorizationCodeGrantFlow.authorize(registeredClient);
		assertThatAuthorization(state, OAuth2ParameterNames.STATE).isNotNull();
		assertThatAuthorization(state, null).isNotNull();

		String authorizationCode = authorizationCodeGrantFlow.submitConsent(registeredClient, state);
		assertThatAuthorization(authorizationCode, OAuth2ParameterNames.CODE).isNotNull();
		assertThatAuthorization(authorizationCode, null).isNotNull();

		Map<String, Object> tokenResponse = authorizationCodeGrantFlow.getTokenResponse(registeredClient,
				authorizationCode);
		String accessToken = (String) tokenResponse.get(OAuth2ParameterNames.ACCESS_TOKEN);
		assertThatAuthorization(accessToken, OAuth2ParameterNames.ACCESS_TOKEN).isNotNull();
		assertThatAuthorization(accessToken, null).isNotNull();

		String refreshToken = (String) tokenResponse.get(OAuth2ParameterNames.REFRESH_TOKEN);
		assertThatAuthorization(refreshToken, OAuth2ParameterNames.REFRESH_TOKEN).isNotNull();
		assertThatAuthorization(refreshToken, null).isNotNull();

		String idToken = (String) tokenResponse.get(OidcParameterNames.ID_TOKEN);
		assertThatAuthorization(idToken, OidcParameterNames.ID_TOKEN).isNotNull();
		assertThatAuthorization(idToken, null).isNotNull();

		OAuth2Authorization authorization = findAuthorization(accessToken, OAuth2ParameterNames.ACCESS_TOKEN);
		assertThat(authorization.getToken(idToken)).isNotNull();

		String scopes = (String) tokenResponse.get(OAuth2ParameterNames.SCOPE);
		OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService
			.findById(registeredClient.getId(), "user");
		assertThat(authorizationConsent).isNotNull();
		assertThat(authorizationConsent.getScopes())
			.containsExactlyInAnyOrder(StringUtils.delimitedListToStringArray(scopes, " "));
	}

	@Test
	public void deviceAuthorizationWhenJpaCoreServicesAutowiredThenSuccess() throws Exception {
		this.spring.register(AuthorizationServerConfig.class).autowire();
		assertThat(this.registeredClientRepository).isInstanceOf(JpaRegisteredClientRepository.class);
		assertThat(this.authorizationService).isInstanceOf(JpaOAuth2AuthorizationService.class);
		assertThat(this.authorizationConsentService).isInstanceOf(JpaOAuth2AuthorizationConsentService.class);

		RegisteredClient registeredClient = messagingClient();
		this.registeredClientRepository.save(registeredClient);

		DeviceAuthorizationGrantFlow deviceAuthorizationGrantFlow = new DeviceAuthorizationGrantFlow(this.mockMvc);
		deviceAuthorizationGrantFlow.setUsername("user");
		deviceAuthorizationGrantFlow.addScope("message.read");
		deviceAuthorizationGrantFlow.addScope("message.write");

		Map<String, Object> deviceAuthorizationResponse = deviceAuthorizationGrantFlow.authorize(registeredClient);
		String userCode = (String) deviceAuthorizationResponse.get(OAuth2ParameterNames.USER_CODE);
		assertThatAuthorization(userCode, OAuth2ParameterNames.USER_CODE).isNotNull();
		assertThatAuthorization(userCode, null).isNotNull();

		String deviceCode = (String) deviceAuthorizationResponse.get(OAuth2ParameterNames.DEVICE_CODE);
		assertThatAuthorization(deviceCode, OAuth2ParameterNames.DEVICE_CODE).isNotNull();
		assertThatAuthorization(deviceCode, null).isNotNull();

		String state = deviceAuthorizationGrantFlow.submitCode(userCode);
		assertThatAuthorization(state, OAuth2ParameterNames.STATE).isNotNull();
		assertThatAuthorization(state, null).isNotNull();

		deviceAuthorizationGrantFlow.submitConsent(registeredClient, state, userCode);

		Map<String, Object> tokenResponse = deviceAuthorizationGrantFlow.getTokenResponse(registeredClient, deviceCode);
		String accessToken = (String) tokenResponse.get(OAuth2ParameterNames.ACCESS_TOKEN);
		assertThatAuthorization(accessToken, OAuth2ParameterNames.ACCESS_TOKEN).isNotNull();
		assertThatAuthorization(accessToken, null).isNotNull();

		String refreshToken = (String) tokenResponse.get(OAuth2ParameterNames.REFRESH_TOKEN);
		assertThatAuthorization(refreshToken, OAuth2ParameterNames.REFRESH_TOKEN).isNotNull();
		assertThatAuthorization(refreshToken, null).isNotNull();

		String scopes = (String) tokenResponse.get(OAuth2ParameterNames.SCOPE);
		OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService
			.findById(registeredClient.getId(), "user");
		assertThat(authorizationConsent).isNotNull();
		assertThat(authorizationConsent.getScopes())
			.containsExactlyInAnyOrder(StringUtils.delimitedListToStringArray(scopes, " "));
	}

	private ObjectAssert<OAuth2Authorization> assertThatAuthorization(String token, String tokenType) {
		return assertThat(findAuthorization(token, tokenType));
	}

	private OAuth2Authorization findAuthorization(String token, String tokenType) {
		return this.authorizationService.findByToken(token, tokenType == null ? null : new OAuth2TokenType(tokenType));
	}

	@EnableWebSecurity
	@EnableAutoConfiguration
	@ComponentScan
	static class AuthorizationServerConfig {

		@Bean
		@Order(Ordered.HIGHEST_PRECEDENCE)
		public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
			OAuth2AuthorizationServerConfigurer authorizationServerConfigurer = OAuth2AuthorizationServerConfigurer
				.authorizationServer();

			// @formatter:off
			http
				.securityMatcher(authorizationServerConfigurer.getEndpointsMatcher())
				.with(authorizationServerConfigurer, (authorizationServer) ->
					authorizationServer
						.oidc(Customizer.withDefaults())	// Enable OpenID Connect 1.0
				)
				.authorizeHttpRequests((authorize) ->
					authorize
						.anyRequest().authenticated()
				)
				.exceptionHandling((exceptions) -> exceptions
					.defaultAuthenticationEntryPointFor(
						new LoginUrlAuthenticationEntryPoint("/login"),
						new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
					)
				);
			// @formatter:on
			return http.build();
		}

		@Bean
		public JWKSource<SecurityContext> jwkSource() {
			JWKSet jwkSet = new JWKSet(TestJwks.DEFAULT_RSA_JWK);
			return new ImmutableJWKSet<>(jwkSet);
		}

		@Bean
		public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
			return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
		}

		@Bean
		public AuthorizationServerSettings authorizationServerSettings() {
			return AuthorizationServerSettings.builder().build();
		}

	}

}