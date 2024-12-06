
package com.chensoul.config;

import java.util.UUID;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.util.Assert;

@Configuration(proxyBeanMethods = false)
public class RegisteredClientRepositoryConfig {

	@Bean
	public RegisteredClientRepository registeredClientRepository(
			@Qualifier("issuer1-data-source") DataSource issuer1DataSource,
			@Qualifier("issuer2-data-source") DataSource issuer2DataSource,
			TenantPerIssuerComponentRegistry componentRegistry) {

		JdbcRegisteredClientRepository issuer1RegisteredClientRepository =
				new JdbcRegisteredClientRepository(new JdbcTemplate(issuer1DataSource));

		// @formatter:off
		issuer1RegisteredClientRepository.save(
				RegisteredClient.withId(UUID.randomUUID().toString())
						.clientId("client-1")
						.clientSecret("{noop}secret")
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
						.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
						.redirectUri("http://127.0.0.1:8080/login/oauth2/code/oidc-client")
						.redirectUri("http://127.0.0.1:8080/authorized")
						.postLogoutRedirectUri("http://127.0.0.1:8080/logged-out")
						.scope(OidcScopes.OPENID)
						.scope(OidcScopes.PROFILE)
						.scope("message.read")
						.scope("message.write")
						.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
						.build()
		);
		// @formatter:on

		JdbcRegisteredClientRepository issuer2RegisteredClientRepository =
				new JdbcRegisteredClientRepository(new JdbcTemplate(issuer2DataSource));

		// @formatter:off
		issuer2RegisteredClientRepository.save(
				RegisteredClient.withId(UUID.randomUUID().toString())
						.clientId("client-2")
						.clientSecret("{noop}secret")
						.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
						.authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
						.authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
						.authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
						.redirectUri("http://127.0.0.1:8080/authorized")
						.postLogoutRedirectUri("http://127.0.0.1:8080/logged-out")
						.scope("message.read")
						.scope("message.write")
						.clientSettings(ClientSettings.builder().requireAuthorizationConsent(true).build())
						.build()
		);
		// @formatter:on

		componentRegistry.register("issuer1", RegisteredClientRepository.class, issuer1RegisteredClientRepository);
		componentRegistry.register("issuer2", RegisteredClientRepository.class, issuer2RegisteredClientRepository);

		return new DelegatingRegisteredClientRepository(componentRegistry);
	}

	private static class DelegatingRegisteredClientRepository implements RegisteredClientRepository {

		private final TenantPerIssuerComponentRegistry componentRegistry;

		private DelegatingRegisteredClientRepository(TenantPerIssuerComponentRegistry componentRegistry) {
			this.componentRegistry = componentRegistry;
		}

		@Override
		public void save(RegisteredClient registeredClient) {
			getRegisteredClientRepository().save(registeredClient);
		}

		@Override
		public RegisteredClient findById(String id) {
			return getRegisteredClientRepository().findById(id);
		}

		@Override
		public RegisteredClient findByClientId(String clientId) {
			return getRegisteredClientRepository().findByClientId(clientId);
		}

		private RegisteredClientRepository getRegisteredClientRepository() {
			RegisteredClientRepository registeredClientRepository =
					this.componentRegistry.get(RegisteredClientRepository.class);
			Assert.state(registeredClientRepository != null,
					"RegisteredClientRepository not found for \"requested\" issuer identifier.");
			return registeredClientRepository;
		}

	}

}