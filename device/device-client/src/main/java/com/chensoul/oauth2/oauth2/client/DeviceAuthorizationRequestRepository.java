package com.chensoul.oauth2.oauth2.client;

import com.chensoul.oauth2.oauth2.client.endpoint.OAuth2DeviceAuthorizationRequest;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;


public interface DeviceAuthorizationRequestRepository<T extends OAuth2DeviceAuthorizationRequest> {

    T loadAuthorizationRequest(HttpServletRequest request);

    void saveAuthorizationRequest(T authorizationRequest, HttpServletRequest request, HttpServletResponse response);

    T removeAuthorizationRequest(HttpServletRequest request, HttpServletResponse response);
}
