package com.chensoul.oauth2.token;

import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;

@FunctionalInterface
public interface AccessTokenLimiter {

  boolean isAllowed(RegisteredClient registeredClient);
}
