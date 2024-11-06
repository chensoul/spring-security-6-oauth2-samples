package com.chensoul.authserver;

import java.util.Map;
import java.util.Set;
import java.util.UUID;
import javax.sql.DataSource;
import org.springframework.boot.ApplicationRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.JdbcOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.client.JdbcRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

@SpringBootApplication
public class AuthserverApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthserverApplication.class, args);
	}

//	@Bean
//	public UserDetailsService userDetailsService() {
//		UserDetails one = User.withDefaultPasswordEncoder().username("one").password("pw").roles("admin", "user").build();
//		UserDetails two = User.withDefaultPasswordEncoder().username("two").password("pw").roles("user").build();
//
//		return new InMemoryUserDetailsManager(one, two);
//	}
}

@Configuration
class UserConfiguration {
	@Bean
	JdbcUserDetailsManager jdbcUserDetailsManager(DataSource dataSource) {
		return new JdbcUserDetailsManager(dataSource);
	}

	@Bean
	ApplicationRunner userRunner(UserDetailsManager userDetailsManager) {
		return args -> {
			var builder = User.builder().roles("USER");
			var users = Map.of("one", "{noop}pw"
				, "two", "{noop}pw"
			);
			users.forEach((username, password) -> {
				if (!userDetailsManager.userExists(username)) {
					userDetailsManager.createUser(builder.username(username).password(password).build());
				}
			});
		};
	}
}

@Configuration
class ClientConfiguration {
	@Bean
	RegisteredClientRepository registeredClientRepository(JdbcTemplate jdbcTemplate) {
		return new JdbcRegisteredClientRepository(jdbcTemplate);
	}

	@Bean
	ApplicationRunner clientsRunner(RegisteredClientRepository repository) {
		return args -> {
			var clientId = "client";
			if (repository.findByClientId(clientId) == null) {
				var registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
					.clientId(clientId)
					.clientSecret("{noop}password")
					.clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
					.authorizationGrantTypes(grantTypes -> grantTypes.addAll(Set.of(
						AuthorizationGrantType.CLIENT_CREDENTIALS,
						AuthorizationGrantType.AUTHORIZATION_CODE,
						AuthorizationGrantType.REFRESH_TOKEN
					)))
					.redirectUri("http://127.0.0.1:8082/login/oauth2/code/spring")
					.scopes(scopes -> scopes.addAll(Set.of("user.read", "user.write", OidcScopes.OPENID)))
					.build();
				repository.save(registeredClient);
			}
		};
	}
}


@Configuration
class AuthorizationConfiguration {
	@Bean
	JdbcOAuth2AuthorizationConsentService jdbcOAuth2AuthorizationConsentService(JdbcOperations jdbcOperations, RegisteredClientRepository repository) {
		return new JdbcOAuth2AuthorizationConsentService(jdbcOperations, repository);
	}

	@Bean
	JdbcOAuth2AuthorizationService jdbcOAuth2AuthorizationService(JdbcOperations jdbcOperations, RegisteredClientRepository repository) {
		return new JdbcOAuth2AuthorizationService(jdbcOperations, repository);
	}
}
