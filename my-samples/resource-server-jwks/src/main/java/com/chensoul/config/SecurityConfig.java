package com.chensoul.config;

import org.springframework.boot.autoconfigure.security.oauth2.resource.servlet.OAuth2ResourceServerAutoConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtGrantedAuthoritiesConverter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * @see OAuth2ResourceServerAutoConfiguration
 */
@Configuration
public class SecurityConfig {

	@Bean
	SecurityFilterChain jwtSecurityFilterChain(HttpSecurity http) throws Exception {
		http.authorizeHttpRequests((authorize) -> authorize.requestMatchers(HttpMethod.GET, "/message/**")
			.hasAuthority("SCOPE_read")
			.requestMatchers(HttpMethod.POST, "/message/**")
			.hasAuthority("SCOPE_write")
			.anyRequest()
			.authenticated()).oauth2ResourceServer(rsc -> rsc.jwt(Customizer.withDefaults()));
		return http.build();
	}

	@Bean
	JwtAuthenticationConverter jwtAuthenticationConverter() {
		// 默认是从 jwt 中取 scope，然后加上 SCOPE_ 前缀
		JwtGrantedAuthoritiesConverter jwtGrantedAuthoritiesConverter = new JwtGrantedAuthoritiesConverter();
		// jwtGrantedAuthoritiesConverter.setAuthoritiesClaimName("authorities");
		// jwtGrantedAuthoritiesConverter.setAuthorityPrefix("");

		JwtAuthenticationConverter jwtAuthenticationConverter = new JwtAuthenticationConverter();
		jwtAuthenticationConverter.setJwtGrantedAuthoritiesConverter(jwtGrantedAuthoritiesConverter);
		return jwtAuthenticationConverter;
	}

}