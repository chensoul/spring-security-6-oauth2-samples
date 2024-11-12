package com.chensoul.config;


import java.io.IOException;
import java.util.Collections;
import java.util.Objects;
import static java.util.Objects.isNull;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import org.springframework.http.HttpRequest;
import org.springframework.http.client.ClientHttpRequestExecution;
import org.springframework.http.client.ClientHttpRequestInterceptor;
import org.springframework.http.client.ClientHttpResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.stereotype.Component;

@RequiredArgsConstructor
@Component
public class OAuth2ClientInterceptor implements ClientHttpRequestInterceptor {
    public static final String AUTHORIZATION = "Authorization";
    public static final String BEARER = "Bearer ";

    private final OAuth2AuthorizedClientManager authorizedClientManager;

    @Override
    public ClientHttpResponse intercept(HttpRequest request, byte[] body, ClientHttpRequestExecution execution) throws IOException {
        OAuth2AuthorizeRequest authorizeRequest = OAuth2AuthorizeRequest.withClientRegistrationId("spring")
                .principal("client")
                .build();
        OAuth2AuthorizedClient authorizedClient = authorizedClientManager.authorize(authorizeRequest);
        final var token = Objects.requireNonNull(authorizedClient).getAccessToken().getTokenValue();
        request.getHeaders().put(AUTHORIZATION, Collections.singletonList(BEARER.concat(token)));
        return execution.execute(request, body);
    }

}