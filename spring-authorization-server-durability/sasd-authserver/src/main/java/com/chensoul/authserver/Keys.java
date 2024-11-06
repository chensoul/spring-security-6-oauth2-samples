package com.chensoul.authserver;

import com.nimbusds.jose.KeySourceException;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSelector;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Date;
import java.util.List;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.event.ApplicationReadyEvent;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationEventPublisher;
import org.springframework.context.ApplicationListener;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.serializer.Deserializer;
import org.springframework.core.serializer.Serializer;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.security.crypto.encrypt.Encryptors;
import org.springframework.security.crypto.encrypt.TextEncryptor;
import org.springframework.security.oauth2.core.OAuth2Token;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.token.DelegatingOAuth2TokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.JwtGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2AccessTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2RefreshTokenGenerator;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenGenerator;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;
import org.springframework.util.FileCopyUtils;

/**
 * TODO Comment
 *
 * @author <a href="mailto:ichensoul@gmail.com">chensoul</a>
 * @since TODO
 */
@Configuration
public class Keys {
	RsaKeyPairRepository.RsaKeyPair generateKeyPair(String keyId, Instant created) {
		var keyPair = generateRsaKey();
		var publicKey = (RSAPublicKey) keyPair.getPublic();
		var privateKey = (RSAPrivateKey) keyPair.getPrivate();
		return new RsaKeyPairRepository.RsaKeyPair(keyId, created, publicKey, privateKey);
	}

	private KeyPair generateRsaKey() {
		try {
			var keyPairGenerator = KeyPairGenerator.getInstance("RSA");
			keyPairGenerator.initialize(2048);
			return keyPairGenerator.genKeyPair();
		} catch (Exception e) {
			throw new IllegalStateException(e);
		}
	}
}

interface RsaKeyPairRepository {
	List<RsaKeyPair> findKeyPairs();

	void save(RsaKeyPair rsaKeyPair);

	record RsaKeyPair(String id, Instant created, RSAPublicKey publicKey, RSAPrivateKey privateKey) {
	}
}

@Component
class JdbcRsaKeyPairRepository implements RsaKeyPairRepository {
	private final JdbcTemplate jdbcTemplate;
	private final RsaPublicKeyConverter rsaPublicKeyConverter;
	private final RsaPrivateKeyConverter rsaPrivateKeyConverter;
	private final RowMapper<RsaKeyPair> keyPairRowMapper;

	public JdbcRsaKeyPairRepository(JdbcTemplate jdbcTemplate, RsaPublicKeyConverter rsaPublicKeyConverter, RsaPrivateKeyConverter rsaPrivateKeyConverter, RowMapper<RsaKeyPair> keyPairRowMapper) {
		this.jdbcTemplate = jdbcTemplate;
		this.rsaPublicKeyConverter = rsaPublicKeyConverter;
		this.rsaPrivateKeyConverter = rsaPrivateKeyConverter;
		this.keyPairRowMapper = keyPairRowMapper;
	}

	@Override
	public List<RsaKeyPair> findKeyPairs() {
		return jdbcTemplate.query("select * from rsa_key_pairs order by created desc", keyPairRowMapper);
	}

	@Override
	public void save(RsaKeyPair rsaKeyPair) {
		try (var privateBaos = new ByteArrayOutputStream(); var publicBaos = new ByteArrayOutputStream()) {
			this.rsaPrivateKeyConverter.serialize(rsaKeyPair.privateKey(), privateBaos);
			this.rsaPublicKeyConverter.serialize(rsaKeyPair.publicKey(), publicBaos);

			var updated = jdbcTemplate.update("insert into rsa_key_pairs (id, created, public_key, private_key) values (?, ?, ?, ?)"
				, rsaKeyPair.id(), new Date(rsaKeyPair.created().toEpochMilli()), publicBaos.toString(), privateBaos.toString());
			Assert.state(updated == 0 || updated == 1, "no more than one record has been updated");
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
}

class RsaKeyPairGeneratedRequestEvent extends ApplicationEvent {
	public RsaKeyPairGeneratedRequestEvent(Instant source) {
		super(source);
	}

	@Override
	public Instant getSource() {
		return (Instant) super.getSource();
	}
}

@Configuration
class KeyConfiguration {
	@Bean
	ApplicationListener<ApplicationReadyEvent> applicationReadyListener(ApplicationEventPublisher publisher, RsaKeyPairRepository repository) {
		return event -> {
			if (repository.findKeyPairs().isEmpty()) {
				publisher.publishEvent(new RsaKeyPairGeneratedRequestEvent(Instant.now()));
			}
		};
	}

	@Bean
	ApplicationListener<RsaKeyPairGeneratedRequestEvent> RsaKeyPairGeneratedRequestListener(Keys keys, RsaKeyPairRepository repository,
																							@Value("${jwt.key.id}") String keyId) {
		return event -> repository.save(keys.generateKeyPair(keyId, event.getSource()));
	}

	@Bean
	TextEncryptor textEncryptor(@Value("${jwt.persistence.password}") String pw, @Value("${jwt.persistence.salt}") String salt) {
		return Encryptors.text(pw, salt);
	}

	@Bean
	NimbusJwtEncoder jwtEncoder(JWKSource<SecurityContext> jwkSource) {
		return new NimbusJwtEncoder(jwkSource);
	}

	@Bean
	OAuth2TokenGenerator<OAuth2Token> delegatingOAuth2TokenGenerator(JwtEncoder encoder, OAuth2TokenCustomizer<JwtEncodingContext> customizer) {
		var generator = new JwtGenerator(encoder);
		generator.setJwtCustomizer(customizer);
		return new DelegatingOAuth2TokenGenerator(generator, new OAuth2AccessTokenGenerator(), new OAuth2RefreshTokenGenerator());
	}

	@Bean
	RsaPrivateKeyConverter rsaPrivateKeyConverter(TextEncryptor textEncryptor) {
		return new RsaPrivateKeyConverter(textEncryptor);
	}

	@Bean
	RsaPublicKeyConverter rsaPublicKeyConverter(TextEncryptor textEncryptor) {
		return new RsaPublicKeyConverter(textEncryptor);
	}
}

class RsaPrivateKeyConverter implements Serializer<RSAPrivateKey>, Deserializer<RSAPrivateKey> {
	private final TextEncryptor textEncryptor;

	public RsaPrivateKeyConverter(TextEncryptor textEncryptor) {
		this.textEncryptor = textEncryptor;
	}

	@Override
	public RSAPrivateKey deserialize(InputStream inputStream) throws IOException {
		try {
			var pem = textEncryptor.decrypt(FileCopyUtils.copyToString(new InputStreamReader(inputStream)));
			var privateKeyPEM = pem.replace("-----BEGIN PRIVATE KEY-----", "").replace("-----END PRIVATE KEY-----", "");
			var encoded = Base64.getMimeDecoder().decode(privateKeyPEM);
			var keyFactory = KeyFactory.getInstance("RSA");
			var keySpec = new PKCS8EncodedKeySpec(encoded);
			return (RSAPrivateKey) keyFactory.generatePrivate(keySpec);
		} catch (Throwable e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public void serialize(RSAPrivateKey object, OutputStream outputStream) throws IOException {
		var pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(object.getEncoded());
		var string = "-----BEGIN PRIVATE KEY-----\n" + Base64.getMimeEncoder()
			.encodeToString(pkcs8EncodedKeySpec.getEncoded()) + "\n-----END PRIVATE KEY-----";
		outputStream.write(textEncryptor.encrypt(string).getBytes());
	}
}

class RsaPublicKeyConverter implements Serializer<RSAPublicKey>, Deserializer<RSAPublicKey> {
	private final TextEncryptor textEncryptor;

	public RsaPublicKeyConverter(TextEncryptor textEncryptor) {
		this.textEncryptor = textEncryptor;
	}

	@Override
	public RSAPublicKey deserialize(InputStream inputStream) throws IOException {
		try {
			var pem = textEncryptor.decrypt(FileCopyUtils.copyToString(new InputStreamReader(inputStream)));
			var publicKeyPEM = pem.replace("-----BEGIN PUBLIC KEY-----", "").replace("-----END PUBLIC KEY-----", "");
			var encoded = Base64.getMimeDecoder().decode(publicKeyPEM);
			var keyFactory = KeyFactory.getInstance("RSA");
			var keySpec = new X509EncodedKeySpec(encoded);
			return (RSAPublicKey) keyFactory.generatePublic(keySpec);
		} catch (Throwable e) {
			throw new IllegalStateException(e);
		}
	}

	@Override
	public void serialize(RSAPublicKey object, OutputStream outputStream) throws IOException {
		var x509EncodedKeySpec = new X509EncodedKeySpec(object.getEncoded());
		var string = "-----BEGIN PUBLIC KEY-----\n" + Base64.getMimeEncoder()
			.encodeToString(x509EncodedKeySpec.getEncoded()) + "\n-----END PUBLIC KEY-----";
		outputStream.write(textEncryptor.encrypt(string).getBytes());
	}
}

@Component
class RsaKeyPairRowMapper implements RowMapper<RsaKeyPairRepository.RsaKeyPair> {
	private final RsaPublicKeyConverter rsaPublicKeyConverter;
	private final RsaPrivateKeyConverter rsaPrivateKeyConverter;

	public RsaKeyPairRowMapper(RsaPublicKeyConverter rsaPublicKeyConverter, RsaPrivateKeyConverter rsaPrivateKeyConverter) {
		this.rsaPublicKeyConverter = rsaPublicKeyConverter;
		this.rsaPrivateKeyConverter = rsaPrivateKeyConverter;
	}

	@Override
	public RsaKeyPairRepository.RsaKeyPair mapRow(ResultSet rs, int rowNum) throws SQLException {
		try {
			var id = rs.getString("id");
			var created = new java.util.Date(rs.getDate("created").getTime()).toInstant();
			var publicKey = rsaPublicKeyConverter.deserializeFromByteArray(rs.getString("public_key").getBytes());
			var privateKey = rsaPrivateKeyConverter.deserializeFromByteArray(rs.getString("private_key").getBytes());
			return new RsaKeyPairRepository.RsaKeyPair(id, created, publicKey, privateKey);
		} catch (IOException e) {
			throw new IllegalStateException(e);
		}
	}
}

@Component
class RsaKeyPairRepositoryJWKSource implements JWKSource<SecurityContext>, OAuth2TokenCustomizer<JwtEncodingContext> {
	private final RsaKeyPairRepository repository;

	public RsaKeyPairRepositoryJWKSource(RsaKeyPairRepository repository) {
		this.repository = repository;
	}

	@Override
	public List<JWK> get(JWKSelector jwkSelector, SecurityContext securityContext) throws KeySourceException {
		var keyPairs = repository.findKeyPairs();
		var result = new ArrayList<JWK>(keyPairs.size());
		for (var keyPair : keyPairs) {
			var rsaKey = new RSAKey.Builder(keyPair.publicKey()).privateKey(keyPair.privateKey()).keyID(keyPair.id()).build();
			if (jwkSelector.getMatcher().matches(rsaKey)) {
				result.add(rsaKey);
			}
		}
		return result;
	}

	@Override
	public void customize(JwtEncodingContext context) {
		var keyPairs = repository.findKeyPairs();
		var kid = keyPairs.get(0).id();
		context.getJwsHeader().keyId(kid);
	}
}
