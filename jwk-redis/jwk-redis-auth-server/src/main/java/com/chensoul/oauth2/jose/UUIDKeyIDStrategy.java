package com.chensoul.oauth2.jose;

import java.util.UUID;

@Deprecated
public class UUIDKeyIDStrategy implements KeyIDStrategy {

  @Override
  public String generateKeyID() {
    return UUID.randomUUID().toString();
  }
}
