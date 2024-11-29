package com.chensoul;

import jakarta.servlet.http.HttpServletRequest;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationManagerResolver;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.authentication.JwtBearerTokenAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.OpaqueTokenAuthenticationProvider;
import org.springframework.security.oauth2.server.resource.introspection.OpaqueTokenIntrospector;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration
public class SecurityConfig {

    @Bean
    SecurityFilterChain securityFilterChain(HttpSecurity http,
                                            AuthenticationManagerResolver<HttpServletRequest> authenticationManagerResolver) throws Exception {
        // @formatter:off
		http
			.authorizeHttpRequests((authorize) -> authorize
				.requestMatchers("/**/message/**").hasAuthority("SCOPE_read")
				.anyRequest().authenticated()
			)
			.oauth2ResourceServer((oauth2) -> oauth2
				.authenticationManagerResolver(authenticationManagerResolver)
			);
		// @formatter:on

        return http.build();
    }

    @Bean
    AuthenticationManagerResolver<HttpServletRequest> multitenantAuthenticationManager(JwtDecoder jwtDecoder,
                                                                                       OpaqueTokenIntrospector opaqueTokenIntrospector) {
        Map<String, AuthenticationManager> authenticationManagers = new HashMap<>();
        authenticationManagers.put("tenantOne", jwt(jwtDecoder));
        authenticationManagers.put("tenantTwo", opaque(opaqueTokenIntrospector));
        return (request) -> {
            String[] pathParts = request.getRequestURI().split("/");
            String tenantId = (pathParts.length > 0) ? pathParts[1]:null;
            // @formatter:off
			return Optional.ofNullable(tenantId)
					.map(authenticationManagers::get)
					.orElseThrow(() -> new IllegalArgumentException("unknown tenant"));
			// @formatter:on
        };
    }

    AuthenticationManager jwt(JwtDecoder jwtDecoder) {
        JwtAuthenticationProvider authenticationProvider = new JwtAuthenticationProvider(jwtDecoder);
        authenticationProvider.setJwtAuthenticationConverter(new JwtBearerTokenAuthenticationConverter());
        return new ProviderManager(authenticationProvider);
    }

    AuthenticationManager opaque(OpaqueTokenIntrospector introspectionClient) {
        return new ProviderManager(new OpaqueTokenAuthenticationProvider(introspectionClient));
    }

}
