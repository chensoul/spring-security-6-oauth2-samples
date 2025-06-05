package com.chensoul;

import com.chensoul.config.SecurityConfig;
import com.chensoul.test.AuthorizationCodeGrantFlow;
import com.chensoul.test.junit.SpringTestContext;
import com.chensoul.test.junit.SpringTestContextExtension;
import org.assertj.core.api.Assertions;
import org.assertj.core.api.ObjectAssert;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Import;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.*;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.util.StringUtils;

import java.util.Map;

/**
 * Tests for the Getting Started section of the reference documentation.
 *
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension.class)
public class SecurityConfigTests {
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
    public void oidcLoginWhenGettingStartedConfigUsedThenSuccess() throws Exception {
        this.spring.register(AuthorizationServerConfig.class).autowire();
        Assertions.assertThat(this.registeredClientRepository).isInstanceOf(InMemoryRegisteredClientRepository.class);
        Assertions.assertThat(this.authorizationService).isInstanceOf(InMemoryOAuth2AuthorizationService.class);
        Assertions.assertThat(this.authorizationConsentService).isInstanceOf(InMemoryOAuth2AuthorizationConsentService.class);

        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("oidc-client");
        Assertions.assertThat(registeredClient).isNotNull();

        AuthorizationCodeGrantFlow authorizationCodeGrantFlow = new AuthorizationCodeGrantFlow(this.mockMvc);
        authorizationCodeGrantFlow.setUsername("user");
        authorizationCodeGrantFlow.addScope(OidcScopes.OPENID);
        authorizationCodeGrantFlow.addScope(OidcScopes.PROFILE);

        String state = authorizationCodeGrantFlow.authorize(registeredClient);
        assertThatAuthorization(state, OAuth2ParameterNames.STATE).isNotNull();
        assertThatAuthorization(state, null).isNotNull();

        String authorizationCode = authorizationCodeGrantFlow.submitConsent(registeredClient, state);
        assertThatAuthorization(authorizationCode, OAuth2ParameterNames.CODE).isNotNull();
        assertThatAuthorization(authorizationCode, null).isNotNull();

        Map<String, Object> tokenResponse = authorizationCodeGrantFlow.getTokenResponse(registeredClient, authorizationCode);
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
        Assertions.assertThat(authorization.getToken(idToken)).isNotNull();

        String scopes = (String) tokenResponse.get(OAuth2ParameterNames.SCOPE);
        OAuth2AuthorizationConsent authorizationConsent = this.authorizationConsentService.findById(
                registeredClient.getId(), "user");
        Assertions.assertThat(authorizationConsent).isNotNull();
        Assertions.assertThat(authorizationConsent.getScopes()).containsExactlyInAnyOrder(
                StringUtils.delimitedListToStringArray(scopes, " "));
    }

    private ObjectAssert<OAuth2Authorization> assertThatAuthorization(String token, String tokenType) {
        return Assertions.assertThat(findAuthorization(token, tokenType));
    }

    private OAuth2Authorization findAuthorization(String token, String tokenType) {
        return this.authorizationService.findByToken(token, tokenType == null ? null : new OAuth2TokenType(tokenType));
    }

    @EnableWebSecurity
    @EnableAutoConfiguration
    @ComponentScan
    @Import(OAuth2AuthorizationServerConfiguration.class)
    static class AuthorizationServerConfig extends SecurityConfig {

        @Bean
        public OAuth2AuthorizationService authorizationService() {
            return new InMemoryOAuth2AuthorizationService();
        }

        @Bean
        public OAuth2AuthorizationConsentService authorizationConsentService() {
            return new InMemoryOAuth2AuthorizationConsentService();
        }

    }

}