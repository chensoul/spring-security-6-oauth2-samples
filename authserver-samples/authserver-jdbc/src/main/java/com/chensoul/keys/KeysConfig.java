package com.chensoul.keys;

import com.chensoul.jose.KeyGeneratorUtils;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.*;

import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.time.Instant;
import java.util.UUID;

//https://github.com/ProductDock/spring-authorization-server-showcase/blob/main/authorization-server/src/main/java/com/productdock/authorizationserver/config/keys/KeysConfig.java
@Configuration
public class KeysConfig {
    private RsaKeyPair generateKeyPair(Instant created) {
        var keyPair = KeyGeneratorUtils.generateRsaKey();
        var publicKey = (RSAPublicKey) keyPair.getPublic();
        var privateKey = (RSAPrivateKey) keyPair.getPrivate();
        return new RsaKeyPair(UUID.randomUUID().toString(), created, publicKey, privateKey);
    }

    @Bean
    ApplicationListener<RsaKeyParGenerationRequestEvent> keyParGenerationRequestEventApplicationListener(RsaKeyPairRepository repository) {
        return event -> repository.save(generateKeyPair(event.getSource()));
    }

    @Bean
    ApplicationListener<ApplicationReadyEvent> applicationReadyEventApplicationListener(
            ApplicationEventPublisher applicationEventPublisher, RsaKeyPairRepository rsaKeyPairRepository) {
        return event -> {
            if (rsaKeyPairRepository.findKeyPairs().isEmpty()) {
                applicationEventPublisher.publishEvent(new RsaKeyParGenerationRequestEvent(Instant.now()));
            }
        };
    }

    @Bean
    public NimbusJwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
        return new NimbusJwtEncoder(jwkSource);
    }

    @Bean
    public OAuth2TokenGenerator<OAuth2Token> delegationOauth2TokenGenerator(
            JwtEncoder jwtEncoder,
            OAuth2TokenCustomizer<JwtEncodingContext> oAuth2TokenCustomizer) {
        var generator = new JwtGenerator(jwtEncoder);
        generator.setJwtCustomizer(oAuth2TokenCustomizer);
        return new DelegatingOAuth2TokenGenerator(
                generator, new OAuth2AccessTokenGenerator(), new OAuth2RefreshTokenGenerator());
    }

    @Bean
    public TextEncryptor textEncryptor(@Value("${jwk.persistence.password}") String password, @Value("${jwk.persistence.salt}") String salt) {
        return Encryptors.text(password, salt);
    }

}