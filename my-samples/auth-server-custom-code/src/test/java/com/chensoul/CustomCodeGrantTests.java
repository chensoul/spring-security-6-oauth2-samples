package com.chensoul;

import com.chensoul.test.junit.SpringTestContext;
import com.chensoul.test.junit.SpringTestContextExtension;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.HttpHeaders;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(SpringTestContextExtension.class)
public class CustomCodeGrantTests {

	public final SpringTestContext spring = new SpringTestContext(this);

	@Autowired
	private RegisteredClientRepository registeredClientRepository;

	@Autowired
	private MockMvc mvc;

	@Test
	public void requestWhenTokenRequestValidThenTokenResponse() throws Exception {
		this.spring.register(AuthorizationServerConfig.class).autowire();

		RegisteredClient registeredClient = this.registeredClientRepository.findByClientId("oidc-client");

		HttpHeaders headers = new HttpHeaders();
		headers.setBasicAuth(registeredClient.getClientId(), registeredClient.getClientSecret().replace("{noop}", ""));

		// @formatter:off
		this.mvc.perform(post("/oauth2/token")
				.param(OAuth2ParameterNames.GRANT_TYPE, "urn:ietf:params:oauth:grant-type:custom_code")
				.param(OAuth2ParameterNames.CODE, "7QR49T1W3")
				.headers(headers))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty());
		// @formatter:on
	}

	@EnableWebSecurity
	@EnableAutoConfiguration
	@ComponentScan
	static class AuthorizationServerConfig {

	}

}