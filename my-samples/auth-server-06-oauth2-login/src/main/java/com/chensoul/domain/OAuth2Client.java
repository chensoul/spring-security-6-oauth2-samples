/**
 * Copyright © 2016-2025 The Thingsboard Authors
 * <p>
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * <p>
 * http://www.apache.org/licenses/LICENSE-2.0
 * <p>
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.chensoul.domain;

import com.fasterxml.jackson.databind.JsonNode;
import lombok.Data;

import java.util.UUID;

@Data
public class OAuth2Client {
    private UUID tenantId;
    private String title;
    private String clientId;
    private String clientSecret;
    private OAuth2MapperConfig mapperConfig;
    private String authorizationUri;
    private String tokenUri;
    private String scope;
    private String platforms;
    private String userInfoUri;
    private String userNameAttributeName;
    private String jwkSetUri;
    private String clientAuthenticationMethod;
    private String loginButtonLabel;
    private String loginButtonIcon;
    private Boolean activateUser;
    private MapperType type;
    private String emailAttributeKey;
    private String firstNameAttributeKey;
    private String lastNameAttributeKey;
    private TenantNameStrategyType tenantNameStrategy;
    private String tenantNamePattern;
    private String customerNamePattern;
    private String url;
    private String username;
    private String password;
    private Boolean sendToken;
    private JsonNode additionalInfo;
}
