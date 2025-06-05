package com.chensoul;

import com.chensoul.config.idtoken.IdTokenSecurityConfig;
import com.chensoul.config.idtoken.IdTokenCustomizerConfig;
import com.chensoul.config.jwt.JwtSecurityConfig;
import com.chensoul.config.jwt.JwtTokenCustomizerConfig;
import com.chensoul.test.AuthorizationCodeGrantFlow;
import com.chensoul.test.junit.SpringTestContext;
import com.chensoul.test.junit.SpringTestContextExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.Import;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.hamcrest.Matchers.equalTo;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

/**
 * Tests for the guide How-to: Customize the OpenID Connect 1.0 UserInfo response.
 *
 * @author Steve Riesenberg
 */
@ExtendWith(SpringTestContextExtension.class)
public class IdTokenSecurityConfigTests {
    public final SpringTestContext spring = new SpringTestContext(this);

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private RegisteredClientRepository registeredClientRepository;

    @Test
    public void userInfoWhenEnabledThenSuccess() throws Exception {
        this.spring.register(AuthorizationServerConfig.class).autowire();

        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("oidc-client");
        assertThat(registeredClient).isNotNull();

        AuthorizationCodeGrantFlow authorizationCodeGrantFlow = new AuthorizationCodeGrantFlow(this.mockMvc);
        authorizationCodeGrantFlow.setUsername("user1");
        authorizationCodeGrantFlow.addScope("read");
        authorizationCodeGrantFlow.addScope("write");

        String state = authorizationCodeGrantFlow.authorize(registeredClient);
        String authorizationCode = authorizationCodeGrantFlow.submitConsent(registeredClient, state);
        Map<String, Object> tokenResponse = authorizationCodeGrantFlow.getTokenResponse(registeredClient, authorizationCode);
        String accessToken = (String) tokenResponse.get(OAuth2ParameterNames.ACCESS_TOKEN);

        this.mockMvc.perform(get("/userinfo")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON_VALUE)))
                .andExpect(jsonPath("sub").value("user1"));
    }

    @Test
    public void userInfoWhenIdTokenCustomizerThenIdTokenClaimsMappedToResponse() throws Exception {
        this.spring.register(AuthorizationServerConfigWithIdTokenCustomizer.class).autowire();

        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("oidc-client");
        assertThat(registeredClient).isNotNull();

        AuthorizationCodeGrantFlow authorizationCodeGrantFlow = new AuthorizationCodeGrantFlow(this.mockMvc);
        authorizationCodeGrantFlow.setUsername("user1");
        authorizationCodeGrantFlow.addScope(OidcScopes.ADDRESS);
        authorizationCodeGrantFlow.addScope(OidcScopes.EMAIL);
        authorizationCodeGrantFlow.addScope(OidcScopes.PHONE);
        authorizationCodeGrantFlow.addScope(OidcScopes.PROFILE);

        String state = authorizationCodeGrantFlow.authorize(registeredClient);
        String authorizationCode = authorizationCodeGrantFlow.submitConsent(registeredClient, state);
        Map<String, Object> tokenResponse = authorizationCodeGrantFlow.getTokenResponse(registeredClient, authorizationCode);
        String accessToken = (String) tokenResponse.get(OAuth2ParameterNames.ACCESS_TOKEN);

        this.mockMvc.perform(get("/userinfo")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON_VALUE)))
                .andExpectAll(
                        jsonPath("sub").value("user1"),
                        jsonPath("name").value("First Last"),
                        jsonPath("given_name").value("First"),
                        jsonPath("family_name").value("Last"),
                        jsonPath("middle_name").value("Middle"),
                        jsonPath("nickname").value("User"),
                        jsonPath("preferred_username").value("user1"),
                        jsonPath("profile").value("https://example.com/user1"),
                        jsonPath("picture").value("https://example.com/user1.jpg"),
                        jsonPath("website").value("https://example.com"),
                        jsonPath("email").value("user1@example.com"),
                        jsonPath("email_verified").value("true"),
                        jsonPath("gender").value("female"),
                        jsonPath("birthdate").value("1970-01-01"),
                        jsonPath("zoneinfo").value("Europe/Paris"),
                        jsonPath("locale").value("en-US"),
                        jsonPath("phone_number").value("+1 (604) 555-1234;ext=5678"),
                        jsonPath("phone_number_verified").value("false"),
                        jsonPath("address.formatted").value("Champ de Mars\n5 Av. Anatole France\n75007 Paris\nFrance"),
                        jsonPath("updated_at").value("1970-01-01T00:00:00Z")
                );
    }

    @Test
    public void userInfoWhenUserInfoMapperThenClaimsMappedToResponse() throws Exception {
        this.spring.register(AuthorizationServerConfigWithJwtTokenCustomizer.class).autowire();

        RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("oidc-client");
        assertThat(registeredClient).isNotNull();

        AuthorizationCodeGrantFlow authorizationCodeGrantFlow = new AuthorizationCodeGrantFlow(this.mockMvc);
        authorizationCodeGrantFlow.setUsername("user1");
        authorizationCodeGrantFlow.addScope("read");
        authorizationCodeGrantFlow.addScope("write");

        String state = authorizationCodeGrantFlow.authorize(registeredClient);
        String authorizationCode = authorizationCodeGrantFlow.submitConsent(registeredClient, state);
        Map<String, Object> tokenResponse = authorizationCodeGrantFlow.getTokenResponse(registeredClient, authorizationCode);
        String accessToken = (String) tokenResponse.get(OAuth2ParameterNames.ACCESS_TOKEN);

        this.mockMvc.perform(get("/userinfo")
                        .header(HttpHeaders.AUTHORIZATION, "Bearer " + accessToken))
                .andExpect(status().isOk())
                .andExpect(header().string(HttpHeaders.CONTENT_TYPE, equalTo(MediaType.APPLICATION_JSON_VALUE)))
                .andExpectAll(
                        jsonPath("sub").value("user1"),
                        jsonPath("claim-1").value("value-1"),
                        jsonPath("claim-2").value("value-2")
                );
    }

    @EnableWebSecurity
    @EnableAutoConfiguration
    @Import(JwtSecurityConfig.class)
    static class AuthorizationServerConfig {

    }

    @EnableWebSecurity
    @Import({IdTokenSecurityConfig.class, IdTokenCustomizerConfig.class})
    static class AuthorizationServerConfigWithIdTokenCustomizer {

    }

    @EnableWebSecurity
    @EnableAutoConfiguration
    @Import({JwtSecurityConfig.class, JwtTokenCustomizerConfig.class})
    static class AuthorizationServerConfigWithJwtTokenCustomizer {

    }

}