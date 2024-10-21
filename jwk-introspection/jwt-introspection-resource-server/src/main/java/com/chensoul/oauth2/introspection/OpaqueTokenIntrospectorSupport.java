package com.chensoul.oauth2.introspection;

import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;


public interface OpaqueTokenIntrospectorSupport {

    OpaqueTokenIntrospector fromOAuth2Introspection(OAuth2Introspection oAuth2Introspection);
}
