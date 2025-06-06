package com.chensoul.support;

import java.util.Set;

public class OAuth2ClientCredentialsGrantAuthorization extends OAuth2AuthorizationGrantAuthorization {

	// @fold:on
	public OAuth2ClientCredentialsGrantAuthorization(String id, String registeredClientId, String principalName,
			Set<String> authorizedScopes, AccessToken accessToken) {
		super(id, registeredClientId, principalName, authorizedScopes, accessToken, null);
	}
	// @fold:off

}