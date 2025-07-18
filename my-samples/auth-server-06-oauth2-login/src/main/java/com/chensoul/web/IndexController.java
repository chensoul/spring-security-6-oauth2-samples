/*
 * Copyright 2002-2024 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.chensoul.web;

import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

/**
 * OAuth2 Log in controller.
 *
 * @author Joe Grandja
 * @author Rob Winch
 */
@Controller
public class IndexController {

	// @GetMapping("/")
	// public String index(Model model, @RegisteredOAuth2AuthorizedClient
	// OAuth2AuthorizedClient authorizedClient,
	// @AuthenticationPrincipal OAuth2User oauth2User) {
	// model.addAttribute("userName", oauth2User.getName());
	// model.addAttribute("userAttributes", oauth2User.getAttributes());
	//
	// model.addAttribute("clientName",
	// authorizedClient.getClientRegistration().getClientName());
	// return "index";
	// }

	@GetMapping("/")
	public String index(Model model, Authentication authentication) {
		model.addAttribute("userName", authentication.getName());

		if (authentication instanceof OAuth2AuthenticationToken) {
			OAuth2AuthenticationToken oAuth2AuthenticationToken = (OAuth2AuthenticationToken) authentication;
			model.addAttribute("clientName", oAuth2AuthenticationToken.getAuthorizedClientRegistrationId());
		}
		if (authentication.getPrincipal() instanceof OAuth2User) {
			OAuth2User oauth2User = (OAuth2User) authentication.getPrincipal();
			model.addAttribute("userAttributes", oauth2User.getAttributes());
		}
		return "index";
	}

}
