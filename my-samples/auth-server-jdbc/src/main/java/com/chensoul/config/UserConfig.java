package com.chensoul.config;

import java.util.Map;
import javax.sql.DataSource;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.provisioning.UserDetailsManager;

@Configuration
public class UserConfig {

	@Bean
	public JdbcUserDetailsManager jdbcUserDetailsManager(DataSource dataSource) {
		return new JdbcUserDetailsManager(dataSource);
	}

	@Bean
	ApplicationRunner usersRunner(UserDetailsManager userDetailsManager) {
		return args -> {
			var users = Map.of("user", User.builder().username("user").password("{noop}password").roles("USER").build(),
					"admin", User.builder().username("admin").password("{noop}password").roles("ADMIN").build());
			users.forEach((username, user) -> {
				if (!userDetailsManager.userExists(username)) {
					userDetailsManager.createUser(user);
				}
			});
		};
	}

}