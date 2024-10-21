package com.chensoul.oauth2.context;

import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.util.Assert;

public class TokenContext {
  private final TokenSettings tokenSettings;

  public TokenContext(TokenSettings tokenSettings) {
    Assert.notNull(tokenSettings, "tokenSettings cannot be null");
    this.tokenSettings = tokenSettings;
  }

  public TokenSettings getTokenSettings() {
    return this.tokenSettings;
  }
}
