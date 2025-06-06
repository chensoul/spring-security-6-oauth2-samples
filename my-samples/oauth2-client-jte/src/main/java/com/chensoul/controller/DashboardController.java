package com.chensoul.controller;

import jakarta.servlet.http.HttpServletRequest;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.annotation.RegisteredOAuth2AuthorizedClient;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping
public class DashboardController {

	@GetMapping("/dashboard")
	public String index(Authentication authentication, HttpServletRequest request, Model model,
			@RegisteredOAuth2AuthorizedClient OAuth2AuthorizedClient authorizedClient) {
		if (authentication.getPrincipal() instanceof UserDetails userDetails) {
			model.addAttribute("userName", userDetails.getUsername());
			model.addAttribute("clientName", "N/A");
		}
		else if (authentication.getPrincipal() instanceof OAuth2User oauth2User) {
			model.addAttribute("userName", oauth2User.getName());
			model.addAttribute("clientName", authorizedClient.getClientRegistration().getClientName());
			model.addAttribute("userAttributes", oauth2User.getAttributes());
		}

		// Add CSRF token
		CsrfToken csrf = (CsrfToken) request.getAttribute(CsrfToken.class.getName());
		if (csrf != null) {
			model.addAttribute("csrf", csrf);
		}

		return "pages/dashboard";
	}

}