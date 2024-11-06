package com.chensoul.processor;

import org.springframework.messaging.Message;
import org.springframework.messaging.MessageChannel;
import org.springframework.messaging.support.ChannelInterceptor;
import org.springframework.messaging.support.MessageBuilder;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;
import org.springframework.util.Assert;

/**
 * TODO Comment
 *
 * @author <a href="mailto:ichensoul@gmail.com">chensoul</a>
 * @since TODO
 */
public class JwtAuthenticationInterceptor implements ChannelInterceptor {
	String headerName;
	JwtAuthenticationProvider jwtAuthenticationProvider;

	public JwtAuthenticationInterceptor(String headerName, JwtAuthenticationProvider jwtAuthenticationProvider) {
		this.headerName = headerName;
		this.jwtAuthenticationProvider = jwtAuthenticationProvider;
	}

	@Override
	public Message<?> preSend(Message<?> message, MessageChannel channel) {
		var token = (String) message.getHeaders().get(headerName);
		Assert.hasText(token, "token cannot be empty");

		var authentication = jwtAuthenticationProvider.authenticate(new BearerTokenAuthenticationToken(token));
		if (authentication != null && authentication.isAuthenticated()) {
			var upt = UsernamePasswordAuthenticationToken.authenticated(authentication.getName(), null, AuthorityUtils.NO_AUTHORITIES);
			return MessageBuilder.fromMessage(message).setHeader(headerName, upt).build();
		}
		return MessageBuilder.fromMessage(message).setHeader(headerName, null).build();
	}
}
