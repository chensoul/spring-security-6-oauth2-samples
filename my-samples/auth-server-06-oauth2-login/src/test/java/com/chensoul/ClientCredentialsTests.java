package com.chensoul;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;

import java.util.Map;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.httpBasic;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
public class ClientCredentialsTests {
    private static final String CLIENT_ID = "credentials-client";
    private static final String CLIENT_SECRET = "credentials-client";

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Autowired
    private MockMvc mockMvc;

    @LocalServerPort
    private long port;

    @Test
    void performTokenRequestWhenValidClientCredentialsThenOk() throws Exception {
        // @formatter:off
		this.mockMvc.perform(post("/oauth2/token")
				.param("grant_type", "client_credentials")
				.param("scope", "read")
				.with(httpBasic(CLIENT_ID, CLIENT_SECRET)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isString())
				.andExpect(jsonPath("$.expires_in").isNumber())
				.andExpect(jsonPath("$.scope").value("read"))
				.andExpect(jsonPath("$.token_type").value("Bearer"));
		// @formatter:on
    }

    @Test
    void performTokenRequestWhenMissingScopeThenOk() throws Exception {
        // @formatter:off
		this.mockMvc.perform(post("/oauth2/token")
				.param("grant_type", "client_credentials")
				.with(httpBasic(CLIENT_ID, CLIENT_SECRET)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").isString())
				.andExpect(jsonPath("$.expires_in").isNumber())
				.andExpect(jsonPath("$.token_type").value("Bearer"));
		// @formatter:on
    }

    @Test
    void performTokenRequestWhenInvalidClientCredentialsThenUnauthorized() throws Exception {
        // @formatter:off
		this.mockMvc.perform(post("/oauth2/token")
				.param("grant_type", "client_credentials")
				.param("scope", "read")
				.with(httpBasic("bad", "password")))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error").value("invalid_client"));
		// @formatter:on
    }

    @Test
    void performTokenRequestWhenMissingGrantTypeThenUnauthorized() throws Exception {
        // @formatter:off
		this.mockMvc.perform(post("/oauth2/token")
				.with(httpBasic("bad", "password")))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error").value("invalid_client"));
		// @formatter:on
    }

    @Test
    void performTokenRequestWhenGrantTypeNotRegisteredThenBadRequest() throws Exception {
        // @formatter:off
		this.mockMvc.perform(post("/oauth2/token")
				.param("grant_type", "client_credentials")
				.with(httpBasic("oidc-client", "oidc-client")))
				.andExpect(status().isBadRequest())
				.andExpect(jsonPath("$.error").value("unauthorized_client"));
		// @formatter:on
    }

    @Test
    void performIntrospectionRequestWhenValidTokenThenOk() throws Exception {
        // @formatter:off
		this.mockMvc.perform(post("/oauth2/introspect")
				.param("token", getAccessToken())
				.with(httpBasic(CLIENT_ID, CLIENT_SECRET)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.active").value("true"))
				.andExpect(jsonPath("$.aud[0]").value(CLIENT_ID))
				.andExpect(jsonPath("$.client_id").value(CLIENT_ID))
				.andExpect(jsonPath("$.exp").isNumber())
				.andExpect(jsonPath("$.iat").isNumber())
				.andExpect(jsonPath("$.iss").value("http://localhost:"+port))
				.andExpect(jsonPath("$.nbf").isNumber())
				.andExpect(jsonPath("$.scope").value("read"))
				.andExpect(jsonPath("$.sub").value(CLIENT_ID))
				.andExpect(jsonPath("$.token_type").value("Bearer"));
		// @formatter:on
    }

    @Test
    void performIntrospectionRequestWhenInvalidCredentialsThenUnauthorized() throws Exception {
        // @formatter:off
		this.mockMvc.perform(post("/oauth2/introspect")
				.param("token", getAccessToken())
				.with(httpBasic("bad", "password")))
				.andExpect(status().isUnauthorized())
				.andExpect(jsonPath("$.error").value("invalid_client"));
		// @formatter:on
    }

    private String getAccessToken() throws Exception {
        // @formatter:off
		MvcResult mvcResult = this.mockMvc.perform(post("http://localhost:" + port + "/oauth2/token")
				.param("grant_type", "client_credentials")
				.param("scope", "read")
				.with(httpBasic(CLIENT_ID, CLIENT_SECRET)))
				.andExpect(status().isOk())
				.andExpect(jsonPath("$.access_token").exists())
				.andReturn();
		// @formatter:on

        String tokenResponseJson = mvcResult.getResponse().getContentAsString();
        Map<String, Object> tokenResponse = this.objectMapper.readValue(tokenResponseJson, new TypeReference<>() {
        });

        return tokenResponse.get("access_token").toString();
    }

}