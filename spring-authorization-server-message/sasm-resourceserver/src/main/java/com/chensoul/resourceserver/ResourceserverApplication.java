package com.chensoul.resourceserver;

import java.security.Principal;
import java.util.Collection;
import java.util.Map;
import org.springframework.amqp.core.AmqpTemplate;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.annotation.Id;
import org.springframework.data.repository.ListCrudRepository;
import org.springframework.integration.amqp.dsl.Amqp;
import org.springframework.integration.dsl.DirectChannelSpec;
import org.springframework.integration.dsl.IntegrationFlow;
import org.springframework.integration.dsl.MessageChannels;
import org.springframework.integration.json.ObjectToJsonTransformer;
import org.springframework.integration.support.MessageBuilder;
import org.springframework.messaging.MessageChannel;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.stereotype.Repository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@SpringBootApplication
public class ResourceserverApplication {

	public static void main(String[] args) {
		SpringApplication.run(ResourceserverApplication.class, args);
	}
}

@Configuration
class EmailRequestIntegrationFlowConfiguration {
	private final String destinationName = "emails";

	@Bean
	IntegrationFlow emailRequestIntegrationFlow(MessageChannel request, AmqpTemplate template) {
		var outboundAmqpAdapter = Amqp
			.outboundAdapter(template)
			.routingKey(destinationName);

		return IntegrationFlow
			.from(request)
			.transform(new ObjectToJsonTransformer())
			.handle(outboundAmqpAdapter)
			.get();
	}

	@Bean
	DirectChannelSpec request() {
		return MessageChannels.direct();
	}
}

@Repository
interface CustomerRepository extends ListCrudRepository<Customer, Integer> {
}

record Customer(@Id Integer id, String name, String email) {
}

@RestController
class EmailController {
	private final MessageChannel request;
	private final CustomerRepository repository;

	public EmailController(MessageChannel request, CustomerRepository repository) {
		this.request = request;
		this.repository = repository;
	}

	@PostMapping("/email")
	public Map<String, Object> email(@AuthenticationPrincipal Jwt jwt, @RequestParam Integer customerId) {
		var token = jwt.getTokenValue();
		var message = MessageBuilder
			.withPayload(repository.findById(customerId))
			.setHeader("jwt", token)
			.build();
		var sent = request.send(message);

		return Map.of("sent", sent, "customerId", customerId);
	}
}

@RestController
class CustomerHttpController {
	private final CustomerRepository customerRepository;

	public CustomerHttpController(CustomerRepository customerRepository) {
		this.customerRepository = customerRepository;
	}

	@GetMapping("/customers")
	public Collection<Customer> customers() {
		return this.customerRepository.findAll();
	}
}


@RestController
class MeHttpController {

	@GetMapping("/me")
	public Map<String, String> principal(Principal principal) {
		return Map.of("name", principal.getName());
	}
}
