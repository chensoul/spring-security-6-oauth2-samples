package com.chensoul.oauth2.config;

import com.chensoul.oauth2.jose.Jwks;
import com.chensoul.oauth2.token.AccessTokenLimiter;
import com.chensoul.oauth2.token.AccessTokenRestrictionCustomizer;
import com.chensoul.oauth2.token.RedisAccessTokenLimiter;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.time.Duration;
import java.util.UUID;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.oauth2.server.authorization.settings.OAuth2TokenFormat;
import org.springframework.security.oauth2.server.authorization.settings.TokenSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;


@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {

  @Bean
  @Order(Ordered.HIGHEST_PRECEDENCE)
  public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
    OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
    return http.exceptionHandling(exceptions -> exceptions.
            authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login"))).build();
  }

  @Bean
  public RegisteredClientRepository registeredClientRepository() {
    RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
            .clientId("client")
            .clientSecret("{noop}secret")
            .clientAuthenticationMethods(s -> {
              s.add(ClientAuthenticationMethod.CLIENT_SECRET_POST);
              s.add(ClientAuthenticationMethod.CLIENT_SECRET_BASIC);
            })
            .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
            .redirectUri("http://127.0.0.1:8070/login/oauth2/code/messaging-client")
            .scope("message.read")
            .clientSettings(ClientSettings.builder()
                    .requireAuthorizationConsent(false)
                    .requireProofKey(false)
                    .build())
            .tokenSettings(TokenSettings.builder()
                    .accessTokenFormat(OAuth2TokenFormat.SELF_CONTAINED)
                    .idTokenSignatureAlgorithm(SignatureAlgorithm.RS256)
                    .accessTokenTimeToLive(Duration.ofSeconds(30 * 60))
                    .refreshTokenTimeToLive(Duration.ofSeconds(60 * 60))
                    .reuseRefreshTokens(true)
                    .setting("accessTokenLimitTimeSeconds", 5 * 60)
                    .setting("accessTokenLimitRate", 3)
                    .build())
            .build();

    return new InMemoryRegisteredClientRepository(registeredClient);
  }

  @Bean
  public AuthorizationServerSettings authorizationServerSettings() {
    return AuthorizationServerSettings.builder()
            .issuer("http://127.0.0.1:8080")
            .build();
  }

  @Bean
  public JWKSource<SecurityContext> jwkSource() {
    RSAKey rsaKey = Jwks.generateRsa();
    JWKSet jwkSet = new JWKSet(rsaKey);
    return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
  }

  @Bean
  @ConditionalOnClass(RedisTemplate.class)
  public AccessTokenLimiter tokenLimiter(RedisTemplate redisTemplate, RedisScript script) {
    return new RedisAccessTokenLimiter(redisTemplate, script);
  }

  @Bean
  @ConditionalOnClass(AccessTokenLimiter.class)
  public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(AccessTokenLimiter tokenLimiter) {
    return new AccessTokenRestrictionCustomizer(tokenLimiter);
  }
}
