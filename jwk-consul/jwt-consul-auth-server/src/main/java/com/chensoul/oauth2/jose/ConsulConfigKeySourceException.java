package com.chensoul.oauth2.jose;

import com.nimbusds.jose.KeySourceException;

public class ConsulConfigKeySourceException extends KeySourceException {
  public ConsulConfigKeySourceException(String message, Throwable cause) {
    super(message, cause);
  }
}
