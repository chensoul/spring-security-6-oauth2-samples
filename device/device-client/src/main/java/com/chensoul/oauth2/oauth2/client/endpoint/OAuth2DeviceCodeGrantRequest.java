package com.chensoul.oauth2.oauth2.client.endpoint;

import org.springframework.security.oauth2.client.endpoint.AbstractOAuth2AuthorizationGrantRequest;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.util.Assert;


public class OAuth2DeviceCodeGrantRequest extends AbstractOAuth2AuthorizationGrantRequest {
    private final OAuth2DeviceAuthorizationRequest deviceAuthorizationRequest;

    public OAuth2DeviceCodeGrantRequest(ClientRegistration clientRegistration, OAuth2DeviceAuthorizationRequest deviceAuthorizationRequest) {
        super(AuthorizationGrantType.DEVICE_CODE, clientRegistration);
        Assert.notNull(deviceAuthorizationRequest, "deviceAuthorizationRequest cannot be null");
        this.deviceAuthorizationRequest = deviceAuthorizationRequest;
    }

    public OAuth2DeviceAuthorizationRequest getDeviceAuthorizationRequest() {
        return deviceAuthorizationRequest;
    }
}
