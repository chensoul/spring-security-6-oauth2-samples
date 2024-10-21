package com.chensoul.oauth2.filter;

import com.chensoul.oauth2.context.TokenContext;
import com.chensoul.oauth2.context.TokenContextHolder;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

public final class TokenContextFilter extends OncePerRequestFilter {

  @Override
  protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
    try {
      Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
      if (authentication instanceof OAuth2ClientAuthenticationToken) {
        OAuth2ClientAuthenticationToken authenticationToken = (OAuth2ClientAuthenticationToken) authentication;
        TokenContext tokenContext = new TokenContext(authenticationToken.getRegisteredClient().getTokenSettings());
        TokenContextHolder.setTokenContext(tokenContext);
        filterChain.doFilter(request, response);
      }
    } finally {
      TokenContextHolder.resetTokenContext();
    }
  }
}
