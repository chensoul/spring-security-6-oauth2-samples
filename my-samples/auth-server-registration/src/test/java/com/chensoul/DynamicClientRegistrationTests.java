package com.chensoul;

import com.chensoul.config.ClientRegistrar;
import com.jayway.jsonpath.JsonPath;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.http.MediaType;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.web.reactive.function.client.WebClient;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

/**
 * Tests for Dynamic Client Registration how-to guide.
 *
 * @author Dmitriy Dubson
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
		classes = { DynamicClientRegistrationTests.AuthorizationServerConfig.class })
@AutoConfigureMockMvc
public class DynamicClientRegistrationTests {

	@Autowired
	private MockMvc mvc;

	@LocalServerPort
	private String port;

	@Test
	public void dynamicallyRegisterClientWithCustomClientMetadata() throws Exception {
		MockHttpServletResponse tokenResponse = this.mvc
			.perform(post("/oauth2/token").with(httpBasic("credentials-client", "credentials-client"))
				.param(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.CLIENT_CREDENTIALS.getValue())
				.param(OAuth2ParameterNames.SCOPE, "client.create")
				.contentType(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
			.andExpect(status().isOk())
			.andExpect(jsonPath("$.access_token").isNotEmpty())
			.andReturn()
			.getResponse();

		String initialAccessToken = JsonPath.parse(tokenResponse.getContentAsString()).read("$.access_token");

		WebClient webClient = WebClient.builder().baseUrl("http://127.0.0.1:%s".formatted(this.port)).build();
		ClientRegistrar clientRegistrar = new ClientRegistrar(webClient);

		clientRegistrar.exampleRegistration(initialAccessToken);
	}

	@EnableAutoConfiguration
	@EnableWebSecurity
	@ComponentScan
	static class AuthorizationServerConfig {

	}

}