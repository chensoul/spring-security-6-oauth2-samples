package com.chensoul.test;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.assertj.core.api.Assertions;
import org.hamcrest.Matchers;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationResponseType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.endpoint.PkceParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class that performs steps of the {@code authorization_code} flow using
 * {@link MockMvc} for testing.
 *
 * @author Steve Riesenberg
 */
public class AuthorizationCodeGrantFlow {
    private static final Pattern HIDDEN_STATE_INPUT_PATTERN = Pattern.compile(".+<input type=\"hidden\" name=\"state\" value=\"([^\"]+)\">.+");
    private static final TypeReference<Map<String, Object>> TOKEN_RESPONSE_TYPE_REFERENCE = new TypeReference<Map<String, Object>>() {
    };

    private final MockMvc mockMvc;

    private String username = "user";

    private Set<String> scopes = new HashSet<>();

    public AuthorizationCodeGrantFlow(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    public static MultiValueMap<String, String> withCodeChallenge() {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(PkceParameterNames.CODE_CHALLENGE, "BqZZ8pTVLsiA3t3tDOys2flJTSH7LoL3Pp5ZqM_YOnE");
        parameters.set(PkceParameterNames.CODE_CHALLENGE_METHOD, "S256");
        return parameters;
    }

    public static MultiValueMap<String, String> withCodeVerifier() {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(PkceParameterNames.CODE_VERIFIER, "yZ6eB-lEB4BBhIzqoDPqXTTATC0Vkgov7qDF8ar2qT4");
        return parameters;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void addScope(String scope) {
        this.scopes.add(scope);
    }

    /**
     * Perform the authorization request and obtain a state parameter.
     *
     * @param registeredClient The registered client
     * @return The state parameter for submitting consent for authorization
     */
    public String authorize(RegisteredClient registeredClient) throws Exception {
        return authorize(registeredClient, null);
    }

    /**
     * Perform the authorization request and obtain a state parameter.
     *
     * @param registeredClient     The registered client
     * @param additionalParameters Additional parameters for the request
     * @return The state parameter for submitting consent for authorization
     */
    public String authorize(RegisteredClient registeredClient, MultiValueMap<String, String> additionalParameters) throws Exception {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(OAuth2ParameterNames.RESPONSE_TYPE, OAuth2AuthorizationResponseType.CODE.getValue());
        parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
        parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
        parameters.set(OAuth2ParameterNames.SCOPE,
                StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));
        parameters.set(OAuth2ParameterNames.STATE, "state");
        if (additionalParameters != null) {
            parameters.addAll(additionalParameters);
        }

        // @formatter:off
		MvcResult mvcResult = this.mockMvc.perform(MockMvcRequestBuilders.get("/oauth2/authorize")
				.queryParams(parameters)
				.with(SecurityMockMvcRequestPostProcessors.user(this.username).roles("USER")))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.header().string("content-type", Matchers.containsString(MediaType.TEXT_HTML_VALUE)))
				.andReturn();
		// @formatter:on
        String responseHtml = mvcResult.getResponse().getContentAsString();
        Matcher matcher = HIDDEN_STATE_INPUT_PATTERN.matcher(responseHtml);

        return matcher.matches() ? matcher.group(1) : null;
    }

    /**
     * Submit consent for the authorization request and obtain an authorization code.
     *
     * @param registeredClient The registered client
     * @param state            The state parameter from the authorization request
     * @return An authorization code
     */
    public String submitConsent(RegisteredClient registeredClient, String state) throws Exception {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
        parameters.set(OAuth2ParameterNames.STATE, state);
        for (String scope : scopes) {
            parameters.add(OAuth2ParameterNames.SCOPE, scope);
        }

        // @formatter:off
		MvcResult mvcResult = this.mockMvc.perform(MockMvcRequestBuilders.post("/oauth2/authorize")
				.params(parameters)
				.with(SecurityMockMvcRequestPostProcessors.user(this.username).roles("USER")))
				.andExpect(MockMvcResultMatchers.status().is3xxRedirection())
				.andReturn();
		// @formatter:on
        String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
        Assertions.assertThat(redirectedUrl).isNotNull();
        Assertions.assertThat(redirectedUrl).matches("\\S+\\?code=.{15,}&state=state");

        String locationHeader = URLDecoder.decode(redirectedUrl, StandardCharsets.UTF_8.name());
        UriComponents uriComponents = UriComponentsBuilder.fromUriString(locationHeader).build();

        return uriComponents.getQueryParams().getFirst("code");
    }

    /**
     * Exchange an authorization code for an access token.
     *
     * @param registeredClient  The registered client
     * @param authorizationCode The authorization code obtained from the authorization request
     * @return The token response
     */
    public Map<String, Object> getTokenResponse(RegisteredClient registeredClient, String authorizationCode) throws Exception {
        return getTokenResponse(registeredClient, authorizationCode, null);
    }

    /**
     * Exchange an authorization code for an access token.
     *
     * @param registeredClient     The registered client
     * @param authorizationCode    The authorization code obtained from the authorization request
     * @param additionalParameters Additional parameters for the request
     * @return The token response
     */
    public Map<String, Object> getTokenResponse(RegisteredClient registeredClient, String authorizationCode, MultiValueMap<String, String> additionalParameters) throws Exception {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
        parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.AUTHORIZATION_CODE.getValue());
        parameters.set(OAuth2ParameterNames.CODE, authorizationCode);
        parameters.set(OAuth2ParameterNames.REDIRECT_URI, registeredClient.getRedirectUris().iterator().next());
        if (additionalParameters != null) {
            parameters.addAll(additionalParameters);
        }

        boolean publicClient = (registeredClient.getClientSecret() == null);
        HttpHeaders headers = new HttpHeaders();
        if (!publicClient) {
            headers.setBasicAuth(registeredClient.getClientId(),
                    registeredClient.getClientSecret().replace("{noop}", ""));
        }

        // @formatter:off
		MvcResult mvcResult = this.mockMvc.perform(MockMvcRequestBuilders.post("/oauth2/token")
				.params(parameters)
				.headers(headers))
				.andExpect(MockMvcResultMatchers.status().isOk())
				.andExpect(MockMvcResultMatchers.header().string(HttpHeaders.CONTENT_TYPE, Matchers.containsString(MediaType.APPLICATION_JSON_VALUE)))
				.andExpect(MockMvcResultMatchers.jsonPath("$.access_token").isNotEmpty())
				.andExpect(MockMvcResultMatchers.jsonPath("$.token_type").isNotEmpty())
				.andExpect(MockMvcResultMatchers.jsonPath("$.expires_in").isNotEmpty())
				.andExpect(publicClient
						? MockMvcResultMatchers.jsonPath("$.refresh_token").doesNotExist()
						: MockMvcResultMatchers.jsonPath("$.refresh_token").isNotEmpty()
				)
				.andExpect(MockMvcResultMatchers.jsonPath("$.scope").isNotEmpty())
				.andExpect(MockMvcResultMatchers.jsonPath("$.id_token").isNotEmpty())
				.andReturn();
		// @formatter:on

        ObjectMapper objectMapper = new ObjectMapper();
        String responseJson = mvcResult.getResponse().getContentAsString();
        return objectMapper.readValue(responseJson, TOKEN_RESPONSE_TYPE_REFERENCE);
    }
}