package com.chensoul.oauthclient;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.cloud.gateway.route.RouteLocator;
import org.springframework.cloud.gateway.route.builder.RouteLocatorBuilder;
import org.springframework.context.annotation.Bean;
import static org.springframework.security.config.Customizer.withDefaults;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;

@SpringBootApplication
public class OauthclientApplication {

	public static void main(String[] args) {
		SpringApplication.run(OauthclientApplication.class, args);
	}

	@Bean
	RouteLocator gateway(RouteLocatorBuilder rlb) {
		var apiPrefix = "/api/";

		return rlb.routes()
			.route(rs -> rs
				.path(apiPrefix + "**")
				.filters(f -> f
					.tokenRelay()
					.rewritePath(apiPrefix + "(?<segment>.*)", "/$\\{segment}")
				)
				.uri("http://127.0.0.1:8081"))
			.route(rs -> rs
				.path("/**").
				uri("http://127.0.0.1:8020")
			)
			.build();
	}

	@Bean
	SecurityWebFilterChain securityFilterChain(ServerHttpSecurity http) {
		http
			.authorizeExchange(authorize -> authorize.anyExchange().authenticated()
			)
			.csrf(ServerHttpSecurity.CsrfSpec::disable)
			.oauth2Login(withDefaults())
			.oauth2Client(withDefaults());

		return http.build();
	}
}
