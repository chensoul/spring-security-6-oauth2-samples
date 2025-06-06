package com.chensoul.domain;

import lombok.Data;

@Data
public class OAuth2BasicMapperConfig {
    private final String emailAttributeKey;
    private final String firstNameAttributeKey;
    private final String lastNameAttributeKey;
    private final TenantNameStrategyType tenantNameStrategy;
    private final String tenantNamePattern;
    private final String customerNamePattern;
    private final String defaultDashboardName;
    private final boolean alwaysFullScreen;
}