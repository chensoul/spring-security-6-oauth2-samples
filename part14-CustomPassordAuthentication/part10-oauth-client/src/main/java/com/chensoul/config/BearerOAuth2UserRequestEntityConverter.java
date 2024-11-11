package com.chensoul.config;

import java.net.URI;
import java.util.Collections;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.RequestEntity;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequestEntityConverter;
import org.springframework.security.oauth2.core.AuthenticationMethod;
import org.springframework.web.util.UriComponentsBuilder;

public class BearerOAuth2UserRequestEntityConverter extends OAuth2UserRequestEntityConverter {
    @Override
    public RequestEntity<?> convert(OAuth2UserRequest userRequest) {
        ClientRegistration clientRegistration = userRequest.getClientRegistration();
        HttpMethod httpMethod = this.getHttpMethod(clientRegistration);
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        URI uri = UriComponentsBuilder.fromUriString(clientRegistration.getProviderDetails().getUserInfoEndpoint().getUri()).build().toUri();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setBearerAuth(userRequest.getAccessToken().getTokenValue());
        RequestEntity request = new RequestEntity(headers, httpMethod, uri);
        return request;
    }

    private HttpMethod getHttpMethod(ClientRegistration clientRegistration) {
        if (AuthenticationMethod.FORM
                .equals(clientRegistration.getProviderDetails().getUserInfoEndpoint().getAuthenticationMethod())) {
            return HttpMethod.POST;
        }
        return HttpMethod.GET;
    }
}