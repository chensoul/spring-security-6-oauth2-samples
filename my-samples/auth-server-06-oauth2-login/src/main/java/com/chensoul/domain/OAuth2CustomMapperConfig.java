package com.chensoul.domain;

import lombok.Data;

@Data
public class OAuth2CustomMapperConfig {

	private final String url;

	private final String username;

	private final String password;

	private final boolean sendToken;

}