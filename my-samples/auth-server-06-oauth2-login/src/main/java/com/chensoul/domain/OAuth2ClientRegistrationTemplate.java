package com.chensoul.domain;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;

@Data
public class OAuth2ClientRegistrationTemplate {
    private String providerId;
    private String authorizationUri;
    private String tokenUri;
    private String scope;
    private String userInfoUri;
    private String userNameAttributeName;
    private String jwkSetUri;
    private String clientAuthenticationMethod;
    private MapperType type;
    private String emailAttributeKey;
    private String firstNameAttributeKey;
    private String lastNameAttributeKey;
    private TenantNameStrategyType tenantNameStrategy;
    private String tenantNamePattern;
    private String customerNamePattern;
    private String comment;
    private String loginButtonIcon;
    private String loginButtonLabel;
    private String helpLink;

    private JsonNode additionalInfo;
}