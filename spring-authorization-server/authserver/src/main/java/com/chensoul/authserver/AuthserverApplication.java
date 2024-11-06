package com.chensoul.authserver;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;

@SpringBootApplication
public class AuthserverApplication {

	public static void main(String[] args) {
		SpringApplication.run(AuthserverApplication.class, args);
	}

	@Bean
	public InMemoryUserDetailsManager inMemoryUserDetailsManager() {
		UserDetails one = User.withDefaultPasswordEncoder().username("one").password("pw").roles("admin", "user").build();
		UserDetails two = User.withDefaultPasswordEncoder().username("two").password("pw").roles("user").build();

		return new InMemoryUserDetailsManager(one, two);
	}
}
