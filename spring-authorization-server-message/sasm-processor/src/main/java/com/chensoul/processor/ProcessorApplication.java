package com.chensoul.processor;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Exchange;
import org.springframework.amqp.core.ExchangeBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.QueueBuilder;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.integration.amqp.dsl.Amqp;
import org.springframework.integration.dsl.DirectChannelSpec;
import org.springframework.integration.dsl.IntegrationFlow;
import org.springframework.integration.dsl.MessageChannels;
import org.springframework.messaging.MessageChannel;
import org.springframework.security.authorization.AuthenticatedAuthorizationManager;
import org.springframework.security.messaging.access.intercept.AuthorizationChannelInterceptor;
import org.springframework.security.messaging.context.SecurityContextChannelInterceptor;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationProvider;

@SpringBootApplication
public class ProcessorApplication {

	public static void main(String[] args) {
		SpringApplication.run(ProcessorApplication.class, args);
	}

}

class Names {
	public static final String RABBITMQ_DESTINATION_NAME = "emails";
	public static final String AUTHORIZATION_HEADER_NAME = "jwt";
}

@Configuration
class IntegerationConfiguration {
	@Bean
	IntegrationFlow inboundRequestsIntegrationFlowPreAuthorization(
		MessageChannel requests, ConnectionFactory connectionFactory) {
		var inboundAmqpAdapter = Amqp.inboundAdapter(connectionFactory, Names.RABBITMQ_DESTINATION_NAME);

		return IntegrationFlow.from(inboundAmqpAdapter)
			.channel(requests)
			.get();
	}

	@Bean
	IntegrationFlow inboundRequestsIntegrationFlowPostAuthorization(MessageChannel requests) {
		return IntegrationFlow
			.from(requests)
			.handle((payload, headers) -> {
				System.out.println("--------------");
				System.out.println(payload.toString());
				headers.forEach((k, v) -> System.out.println(k + "=" + v));
				return null;
			})
			.get();
	}

	@Bean
	DirectChannelSpec requests(JwtAuthenticationProvider jwtAuthenticationProvider) {
		return MessageChannels
			.direct()
			.interceptor(
				new JwtAuthenticationInterceptor(Names.AUTHORIZATION_HEADER_NAME, jwtAuthenticationProvider),
				new SecurityContextChannelInterceptor(Names.AUTHORIZATION_HEADER_NAME),
				new AuthorizationChannelInterceptor(AuthenticatedAuthorizationManager.authenticated())
			);
	}

	@Bean
	Queue queue() {
		return QueueBuilder.durable(Names.RABBITMQ_DESTINATION_NAME).build();
	}

	@Bean
	Exchange exchange() {
		return ExchangeBuilder.directExchange(Names.RABBITMQ_DESTINATION_NAME).build();
	}

	@Bean
	Binding binding() {
		return BindingBuilder.bind(queue()).to(exchange()).with(Names.RABBITMQ_DESTINATION_NAME).noargs();
	}
}

@Configuration
class SecurityConfiguration {
	@Bean
	JwtAuthenticationProvider jwtAuthenticationProvider(JwtDecoder decoder) {
		return new JwtAuthenticationProvider(decoder);
	}

	@Bean
	JwtDecoder jwtDecoder(@Value("${spring.security.oauth2.authorizationserver.issuer}") String issuerUri) {
		return NimbusJwtDecoder.withIssuerLocation(issuerUri).build();
	}

	@Bean
	JwtAuthenticationConverter jwtAuthenticationConverter() {
		return new JwtAuthenticationConverter();
	}

}
