package com.chensoul.oauth2.jose;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.OctetSequenceKey;
import com.nimbusds.jose.jwk.RSAKey;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.UUID;
import javax.crypto.SecretKey;

public final class Jwks {

  private Jwks() {
  }

  public static RSAKey generateRsa(PublicKey publicKey, PrivateKey privateKey) {
    return new RSAKey.Builder((RSAPublicKey) publicKey)
            .privateKey((RSAPrivateKey) privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
  }

  public static RSAKey generateRsa() {
    KeyPair keyPair = KeyGeneratorUtils.generateRsaKey();
    return generateRsa(keyPair.getPublic(), keyPair.getPrivate());
  }

  public static ECKey generateEc() {
    KeyPair keyPair = KeyGeneratorUtils.generateEcKey();
    ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();
    ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
    Curve curve = Curve.forECParameterSpec(publicKey.getParams());
    return new ECKey.Builder(curve, publicKey)
            .privateKey(privateKey)
            .keyID(UUID.randomUUID().toString())
            .build();
  }

  public static OctetSequenceKey generateSecret() {
    SecretKey secretKey = KeyGeneratorUtils.generateSecretKey();
    return new OctetSequenceKey.Builder(secretKey)
            .keyID(UUID.randomUUID().toString())
            .build();
  }
}
