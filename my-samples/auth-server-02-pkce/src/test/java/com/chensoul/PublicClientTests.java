package com.chensoul;

import com.chensoul.test.AuthorizationCodeGrantFlow;
import com.chensoul.test.junit.SpringTestContext;
import com.chensoul.test.junit.SpringTestContextExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.endpoint.OidcParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static com.chensoul.test.AuthorizationCodeGrantFlow.withCodeChallenge;
import static com.chensoul.test.AuthorizationCodeGrantFlow.withCodeVerifier;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension.class)
public class pkceClientTests {
    public final SpringTestContext spring = new SpringTestContext(this);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Test
    public void oidcLoginWhenpkceClientThenSuccess() throws Exception {
        this.spring.register(AuthorizationServerConfig.class).autowire();

        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("pkce-client");
        assertThat(registeredClient).isNotNull();

        AuthorizationCodeGrantFlow authorizationCodeGrantFlow = new AuthorizationCodeGrantFlow(this.mockMvc);
        authorizationCodeGrantFlow.setUsername("user");
        authorizationCodeGrantFlow.addScope(OidcScopes.OPENID);
        authorizationCodeGrantFlow.addScope(OidcScopes.PROFILE);

        String state = authorizationCodeGrantFlow.authorize(registeredClient, withCodeChallenge());
        assertThat(state).isNotNull();

        String authorizationCode = authorizationCodeGrantFlow.submitConsent(registeredClient, state);
        assertThat(authorizationCode).isNotNull();

        Map<String, Object> tokenResponse = authorizationCodeGrantFlow.getTokenResponse(registeredClient,
                authorizationCode, withCodeVerifier());
        assertThat(tokenResponse.get(OAuth2ParameterNames.ACCESS_TOKEN)).isNotNull();
        // Note: Refresh tokens are not issued to public clients
        assertThat(tokenResponse.get(OAuth2ParameterNames.REFRESH_TOKEN)).isNull();
        assertThat(tokenResponse.get(OidcParameterNames.ID_TOKEN)).isNotNull();
    }

    @EnableWebSecurity
    @EnableAutoConfiguration
    @ComponentScan
    static class AuthorizationServerConfig {

    }

}