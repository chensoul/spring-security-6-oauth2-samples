package com.chensoul.oauth2.jose;

import com.nimbusds.jose.jwk.JWK;

@FunctionalInterface
public interface KeyIDStrategy {

    String generateKeyID();
}
