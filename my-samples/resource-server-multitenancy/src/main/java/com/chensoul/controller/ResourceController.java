
package com.chensoul.controller;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@Slf4j
@RestController
public class ResourceController {

	@GetMapping("/")
	public String index(@AuthenticationPrincipal Jwt jwt) {
		log.info("jwt: {}", jwt.getClaims());
		return String.format("Hello, %s!", jwt.getSubject());
	}

	@GetMapping("/message")
	public String message() {
		return "secret message";
	}

	@PostMapping("/message")
	public String createMessage(@RequestBody String message) {
		return String.format("Message was created. Content: %s", message);
	}

}