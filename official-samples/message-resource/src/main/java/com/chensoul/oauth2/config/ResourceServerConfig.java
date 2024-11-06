package com.chensoul.oauth2.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class ResourceServerConfig {
    /*
        NOTE:
        The `NimbusJwtDecoder` `@Bean` autoconfigured by Spring Boot will contain
        an `OAuth2TokenValidator<Jwt>` of type `X509CertificateThumbprintValidator`.
        This is the validator responsible for validating the `x5t#S256` claim (if available)
        in the `Jwt` against the SHA-256 Thumbprint of the supplied `X509Certificate`.
     */
    // @formatter:off
	@Bean
	SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
		http
			.securityMatcher("/messages/**")
				.authorizeHttpRequests(authorize ->
						authorize.requestMatchers("/messages/**").hasAuthority("SCOPE_message.read")
				)
				.oauth2ResourceServer(oauth2ResourceServer ->
						oauth2ResourceServer.jwt(Customizer.withDefaults())
				);
		return http.build();
	}
	// @formatter:on

}