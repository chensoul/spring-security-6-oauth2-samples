package com.chensoul.oauth2.jose;

public class TimestampKeyIDStrategy implements KeyIDStrategy {
  @Override
  public String generateKeyID() {
    return String.valueOf(System.currentTimeMillis());
  }
}
