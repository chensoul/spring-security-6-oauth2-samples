package com.chensoul.controller;

import static org.springframework.security.oauth2.client.web.reactive.function.client.ServletOAuth2AuthorizedClientExchangeFilterFunction.clientRegistrationId;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.reactive.function.client.WebClient;

@Controller
@RequestMapping(path = { "/webclient", "/public/webclient" })
public class WebClientController {

	private final WebClient webClient;

	public WebClientController(WebClient webClient) {
		this.webClient = webClient;
	}

	@GetMapping("/explicit")
	String explicit(Model model) {
		// @formatter:off
		String body = this.webClient
				.get()
                .uri("https://api.github.com/user/repos")
				.attributes(clientRegistrationId("github"))
				.retrieve()
				.bodyToMono(String.class)
				.block();
		// @formatter:on
		model.addAttribute("body", body);
		return "response";
	}

	@GetMapping("/implicit")
	String implicit(Model model) {
		// @formatter:off
		String body = this.webClient
				.get()
                .uri("https://api.github.com/user/repos")
				.retrieve()
				.bodyToMono(String.class)
				.block();
		// @formatter:on
		model.addAttribute("body", body);
		return "response";
	}

}