package com.chensoul.resourceserver;

import java.util.Map;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class ResourceserverApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResourceserverApplication.class, args);
	}
}

@Service
class GreetingsService {
	public Map<String, String> greet() {
		Jwt jwt = (Jwt) SecurityContextHolder.getContext().getAuthentication().getPrincipal();
		return Map.of("message", "hello, " + jwt.getSubject());
	}
}

@RestController
@RequestMapping
class GreetingsController {
	private final GreetingsService greetingsService;

	public GreetingsController(GreetingsService greetingsService) {
		this.greetingsService = greetingsService;
	}

	@GetMapping("/")
	@PreAuthorize("hasAuthority('SCOPE_user.read')")
	public Map<String, String> hello() {
		return greetingsService.greet();
	}
}
