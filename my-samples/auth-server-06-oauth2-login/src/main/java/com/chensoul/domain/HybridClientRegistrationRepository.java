package com.chensoul.domain;

import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.stereotype.Component;

@Component
public class HybridClientRegistrationRepository implements ClientRegistrationRepository {
    private static final String defaultRedirectUriTemplate = "{baseUrl}/login/oauth2/code/{registrationId}";

//    @Autowired
//    private OAuth2ClientService oAuth2ClientService;

    @Override
    public ClientRegistration findByRegistrationId(String registrationId) {
//        OAuth2Client oAuth2Client = oAuth2ClientService.findOAuth2ClientById(TenantId.SYS_TENANT_ID, new OAuth2ClientId(UUID.fromString(registrationId)));
//        return oAuth2Client == null ?
//                null : toSpringClientRegistration(oAuth2Client);
        return null;
    }

    private ClientRegistration toSpringClientRegistration(OAuth2Client oAuth2Client) {
        String registrationId = oAuth2Client.getClientId();

        // NONE is used if we need pkce-based code challenge
        ClientAuthenticationMethod authMethod = ClientAuthenticationMethod.NONE;
        if (oAuth2Client.getClientAuthenticationMethod().equals("POST")) {
            authMethod = ClientAuthenticationMethod.CLIENT_SECRET_POST;
        } else if (oAuth2Client.getClientAuthenticationMethod().equals("BASIC")) {
            authMethod = ClientAuthenticationMethod.CLIENT_SECRET_BASIC;
        }

        return ClientRegistration.withRegistrationId(registrationId)
                .clientName(oAuth2Client.getTitle())
                .clientId(oAuth2Client.getClientId())
                .authorizationUri(oAuth2Client.getAuthorizationUri())
                .clientSecret(oAuth2Client.getClientSecret())
                .tokenUri(oAuth2Client.getTokenUri())
                .scope(oAuth2Client.getScope())
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .userInfoUri(oAuth2Client.getUserInfoUri())
                .userNameAttributeName(oAuth2Client.getUserNameAttributeName())
                .jwkSetUri(oAuth2Client.getJwkSetUri())
                .clientAuthenticationMethod(authMethod)
                .redirectUri(defaultRedirectUriTemplate)
                .build();
    }
}