package com.chensoul.config;

import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoders;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtIssuerAuthenticationManagerResolver;
import org.springframework.security.web.SecurityFilterChain;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * @see OAuth2ResourceServerAutoConfiguration
 */
@Configuration
public class SecurityConfig {

	@Bean
	SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {
		Map<String, AuthenticationManager> authenticationManagers = new HashMap<>();
		JwtIssuerAuthenticationManagerResolver authenticationManagerResolver = new JwtIssuerAuthenticationManagerResolver(
				authenticationManagers::get);

		List<String> issuers = new ArrayList<>();
		issuers.add("http://localhost:9000/issuer1");
		issuers.add("http://localhost:9000/issuer2");
		issuers.stream().forEach(issuer -> addManager(authenticationManagers, issuer));

		http.authorizeHttpRequests((authorize) -> authorize.requestMatchers(HttpMethod.GET, "/message/**")
			.hasAuthority("SCOPE_read")
			.requestMatchers(HttpMethod.POST, "/message/**")
			.hasAuthority("SCOPE_write")
			.anyRequest()
			.authenticated())
			.oauth2ResourceServer(oauth2 -> oauth2.authenticationManagerResolver(authenticationManagerResolver));
		return http.build();
	}

	private void addManager(Map<String, AuthenticationManager> authenticationManagers, String issuer) {
		JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(
				JwtDecoders.fromIssuerLocation(issuer));
		authenticationManagers.put(issuer, authenticationProvider::authenticate);
	}

}