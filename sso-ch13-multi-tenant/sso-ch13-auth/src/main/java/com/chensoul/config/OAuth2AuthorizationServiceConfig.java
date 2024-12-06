
package com.chensoul.config;

import javax.sql.DataSource;

import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.util.Assert;

@Configuration(proxyBeanMethods = false)
public class OAuth2AuthorizationServiceConfig {

	@Bean
	public OAuth2AuthorizationService authorizationService(
			@Qualifier("issuer1-data-source") DataSource issuer1DataSource,
			@Qualifier("issuer2-data-source") DataSource issuer2DataSource,
			TenantPerIssuerComponentRegistry componentRegistry,
			RegisteredClientRepository registeredClientRepository) {

		componentRegistry.register("issuer1", OAuth2AuthorizationService.class,
				new JdbcOAuth2AuthorizationService(
						new JdbcTemplate(issuer1DataSource), registeredClientRepository));
		componentRegistry.register("issuer2", OAuth2AuthorizationService.class,
				new JdbcOAuth2AuthorizationService(
						new JdbcTemplate(issuer2DataSource), registeredClientRepository));

		return new DelegatingOAuth2AuthorizationService(componentRegistry);
	}

	private static class DelegatingOAuth2AuthorizationService implements OAuth2AuthorizationService {

		private final TenantPerIssuerComponentRegistry componentRegistry;

		private DelegatingOAuth2AuthorizationService(TenantPerIssuerComponentRegistry componentRegistry) {
			this.componentRegistry = componentRegistry;
		}

		@Override
		public void save(OAuth2Authorization authorization) {
			getAuthorizationService().save(authorization);
		}

		@Override
		public void remove(OAuth2Authorization authorization) {
			getAuthorizationService().remove(authorization);
		}

		@Override
		public OAuth2Authorization findById(String id) {
			return getAuthorizationService().findById(id);
		}

		@Override
		public OAuth2Authorization findByToken(String token, OAuth2TokenType tokenType) {
			return getAuthorizationService().findByToken(token, tokenType);
		}

		private OAuth2AuthorizationService getAuthorizationService() {
			OAuth2AuthorizationService authorizationService =
					this.componentRegistry.get(OAuth2AuthorizationService.class);
			Assert.state(authorizationService != null,
					"OAuth2AuthorizationService not found for \"requested\" issuer identifier.");
			return authorizationService;
		}

	}

}