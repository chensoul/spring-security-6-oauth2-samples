package com.chensoul.oauth2.jose;

@FunctionalInterface
public interface KeyIDStrategy {
  String generateKeyID();
}
