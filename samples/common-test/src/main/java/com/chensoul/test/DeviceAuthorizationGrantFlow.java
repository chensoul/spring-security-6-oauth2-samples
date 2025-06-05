package com.chensoul.test;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.assertj.core.api.Assertions;
import org.hamcrest.Matchers;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockMvcRequestBuilders;
import org.springframework.test.web.servlet.result.MockMvcResultMatchers;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class that performs steps of the {@code urn:ietf:params:oauth:grant-type:device_code}
 * flow using {@link MockMvc} for testing.
 *
 * @author Steve Riesenberg
 */
public class DeviceAuthorizationGrantFlow {
    private static final Pattern HIDDEN_STATE_INPUT_PATTERN = Pattern.compile(".+<input type=\"hidden\" name=\"state\" value=\"([^\"]+)\">.+");
    private static final TypeReference<Map<String, Object>> JSON_RESPONSE_TYPE_REFERENCE = new TypeReference<>() {
    };

    private final MockMvc mockMvc;

    private String username = "user";

    private Set<String> scopes = new HashSet<>();

    public DeviceAuthorizationGrantFlow(MockMvc mockMvc) {
        this.mockMvc = mockMvc;
    }

    public void setUsername(String username) {
        this.username = username;
    }

    public void addScope(String scope) {
        this.scopes.add(scope);
    }

    /**
     * Perform the device authorization request and obtain the response
     * containing a user code and device code.
     *
     * @param registeredClient The registered client
     * @return The device authorization response
     */
    public Map<String, Object> authorize(RegisteredClient registeredClient) throws Exception {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
        parameters.set(OAuth2ParameterNames.SCOPE,
                StringUtils.collectionToDelimitedString(registeredClient.getScopes(), " "));

        HttpHeaders basicAuth = new HttpHeaders();
        basicAuth.setBasicAuth(registeredClient.getClientId(), "secret");

        MvcResult mvcResult = this.mockMvc.perform(MockMvcRequestBuilders.post("/oauth2/device_authorization")
                        .params(parameters)
                        .headers(basicAuth))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header().string(HttpHeaders.CONTENT_TYPE, Matchers.containsString(MediaType.APPLICATION_JSON_VALUE)))
                .andExpect(MockMvcResultMatchers.jsonPath("$.user_code").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.device_code").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.verification_uri").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.verification_uri_complete").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.expires_in").isNotEmpty())
                .andReturn();

        ObjectMapper objectMapper = new ObjectMapper();
        String responseJson = mvcResult.getResponse().getContentAsString();
        return objectMapper.readValue(responseJson, JSON_RESPONSE_TYPE_REFERENCE);
    }

    /**
     * Submit the user code and obtain a state parameter from the consent screen.
     *
     * @param userCode The user code from the device authorization request
     * @return The state parameter for submitting consent for authorization
     */
    public String submitCode(String userCode) throws Exception {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(OAuth2ParameterNames.USER_CODE, userCode);

        MvcResult mvcResult = this.mockMvc.perform(MockMvcRequestBuilders.get("/oauth2/device_verification")
                        .queryParams(parameters)
                        .with(SecurityMockMvcRequestPostProcessors.user(this.username).roles("USER")))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header().string(HttpHeaders.CONTENT_TYPE, Matchers.containsString(MediaType.TEXT_HTML_VALUE)))
                .andReturn();
        String responseHtml = mvcResult.getResponse().getContentAsString();
        Matcher matcher = HIDDEN_STATE_INPUT_PATTERN.matcher(responseHtml);

        return matcher.matches() ? matcher.group(1) : null;
    }

    /**
     * Submit consent for the device authorization request.
     *
     * @param registeredClient The registered client
     * @param state            The state parameter from the consent screen
     * @param userCode         The user code from the device authorization request
     */
    public void submitConsent(RegisteredClient registeredClient, String state, String userCode) throws Exception {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(OAuth2ParameterNames.CLIENT_ID, registeredClient.getClientId());
        parameters.set(OAuth2ParameterNames.STATE, state);
        for (String scope : this.scopes) {
            parameters.add(OAuth2ParameterNames.SCOPE, scope);
        }
        parameters.set(OAuth2ParameterNames.USER_CODE, userCode);

        MvcResult mvcResult = this.mockMvc.perform(MockMvcRequestBuilders.post("/oauth2/device_verification")
                        .params(parameters)
                        .with(SecurityMockMvcRequestPostProcessors.user(this.username).roles("USER")))
                .andExpect(MockMvcResultMatchers.status().is3xxRedirection())
                .andReturn();
        String redirectedUrl = mvcResult.getResponse().getRedirectedUrl();
        Assertions.assertThat(redirectedUrl).isNotNull();
        Assertions.assertThat(redirectedUrl).isEqualTo("/?success");
    }

    /**
     * Exchange a device code for an access token.
     *
     * @param registeredClient The registered client
     * @param deviceCode       The device code obtained from the device authorization request
     * @return The token response
     */
    public Map<String, Object> getTokenResponse(RegisteredClient registeredClient, String deviceCode) throws Exception {
        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.set(OAuth2ParameterNames.GRANT_TYPE, AuthorizationGrantType.DEVICE_CODE.getValue());
        parameters.set(OAuth2ParameterNames.DEVICE_CODE, deviceCode);

        HttpHeaders basicAuth = new HttpHeaders();
        basicAuth.setBasicAuth(registeredClient.getClientId(), "secret");

        MvcResult mvcResult = this.mockMvc.perform(MockMvcRequestBuilders.post("/oauth2/token")
                        .params(parameters)
                        .headers(basicAuth))
                .andExpect(MockMvcResultMatchers.status().isOk())
                .andExpect(MockMvcResultMatchers.header().string(HttpHeaders.CONTENT_TYPE, Matchers.containsString(MediaType.APPLICATION_JSON_VALUE)))
                .andExpect(MockMvcResultMatchers.jsonPath("$.access_token").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.refresh_token").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.token_type").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.scope").isNotEmpty())
                .andExpect(MockMvcResultMatchers.jsonPath("$.expires_in").isNotEmpty())
                .andReturn();

        ObjectMapper objectMapper = new ObjectMapper();
        String responseJson = mvcResult.getResponse().getContentAsString();
        return objectMapper.readValue(responseJson, JSON_RESPONSE_TYPE_REFERENCE);
    }
}