package com.chensoul;

import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ResourceController {

	@GetMapping("/{tenantId}")
	public String index(@AuthenticationPrincipal OAuth2AuthenticatedPrincipal token,
			@PathVariable("tenantId") String tenantId) {
		String subject = token.getAttribute("sub");
		return String.format("Hello, %s for %s!", subject, tenantId);
	}

	@GetMapping("/{tenantId}/message")
	public String message(@PathVariable("tenantId") String tenantId) {
		return String.format("secret message for %s", tenantId);
	}

}
