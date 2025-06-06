package com.chensoul.keys;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class RsaKeyPairRepositoryJWKSource
		implements JWKSource<SecurityContext>, OAuth2TokenCustomizer<JwtEncodingContext> {

	private final RsaKeyPairRepository keyPairRepository;

	public RsaKeyPairRepositoryJWKSource(RsaKeyPairRepository keyPairRepository) {
		this.keyPairRepository = keyPairRepository;
	}

	@Override
	public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) {
		return keyPairRepository.findKeyPairs()
			.stream()
			.map(keyPair -> new RSAKey.Builder(keyPair.publicKey()).privateKey(keyPair.privateKey())
				.keyID(keyPair.id())
				.build())
			.filter(rsaKey -> jwkSelector.getMatcher().matches(rsaKey))
			.map(JWK.class::cast)
			.toList();
	}

	@Override
	public void customize(JwtEncodingContext context) {
		List<RsaKeyPair> keyPairs = keyPairRepository.findKeyPairs();
		if (!keyPairs.isEmpty()) {
			String kid = keyPairs.get(0).id();
			context.getJwsHeader().keyId(kid);
		}
	}

}