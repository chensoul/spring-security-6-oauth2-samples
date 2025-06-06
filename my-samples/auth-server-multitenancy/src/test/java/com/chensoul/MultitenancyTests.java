package com.chensoul;

import org.junit.jupiter.api.Test;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.autoconfigure.data.jpa.JpaRepositoriesAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for the guide How-to: Implement Multitenancy.
 *
 * @author Joe Grandja
 */
@SpringBootTest(classes = { MultitenancyTests.AuthorizationServerConfig.class })
@AutoConfigureMockMvc
public class MultitenancyTests {

	@Autowired
	private MockMvc mvc;

	@Test
	public void requestWhenTokenRequestForIssuer1ThenTokenResponse() throws Exception {
		// @formatter:off
		this.mvc.perform(post("/issuer1/oauth2/token")
						.with(httpBasic("client-1", "secret"))
						.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
						.param(OAuth2ParameterNames.SCOPE, "scope-1")
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty());
		// @formatter:on
	}

	@Test
	public void requestWhenTokenRequestForIssuer1WithInvalidClientThenUnauthorized() throws Exception {
		// @formatter:off
		this.mvc.perform(post("/issuer1/oauth2/token")
						.with(httpBasic("client-2", "secret"))
						.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
						.param(OAuth2ParameterNames.SCOPE, "scope-2")
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
				.andExpect(status().isUnauthorized());
		// @formatter:on
	}

	@Test
	public void requestWhenTokenRequestForIssuer2ThenTokenResponse() throws Exception {
		// @formatter:off
		this.mvc.perform(post("/issuer2/oauth2/token")
						.with(httpBasic("client-2", "secret"))
						.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
						.param(OAuth2ParameterNames.SCOPE, "scope-2")
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isNotEmpty());
		// @formatter:on
	}

	@Test
	public void requestWhenTokenRequestForIssuer2WithInvalidClientThenUnauthorized() throws Exception {
		// @formatter:off
		this.mvc.perform(post("/issuer2/oauth2/token")
						.with(httpBasic("client-1", "secret"))
						.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
						.param(OAuth2ParameterNames.SCOPE, "scope-1")
						.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
				.andExpect(status().isUnauthorized());
		// @formatter:on
	}

	@EnableAutoConfiguration(exclude = JpaRepositoriesAutoConfiguration.class)
	@EnableWebSecurity
	@ComponentScan
	static class AuthorizationServerConfig {

	}

}