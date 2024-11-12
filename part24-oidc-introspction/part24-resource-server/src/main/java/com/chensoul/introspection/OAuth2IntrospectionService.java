package com.chensoul.introspection;

public interface OAuth2IntrospectionService {

    OAuth2Introspection loadIntrospection(String issuer);

    void saveOAuth2Introspection(OAuth2Introspection authorizedClient);

    void removeOAuth2Introspection(String issuer);
}
