package com.chensoul.domain;

import lombok.Data;

@Data
public class OAuth2MapperConfig {

	private boolean allowUserCreation;

	private boolean activateUser;

	private MapperType type;

	private OAuth2BasicMapperConfig basic;

	private OAuth2CustomMapperConfig custom;

}