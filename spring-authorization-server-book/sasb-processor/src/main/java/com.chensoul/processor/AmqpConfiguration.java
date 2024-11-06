package com.chensoul.processor;

import static com.chensoul.processor.Constants.RABBITMQ_DESTINATION_NAME;
import org.springframework.amqp.core.*;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
class AmqpConfiguration {

    @Bean
    Queue queue() {
        return QueueBuilder.durable(RABBITMQ_DESTINATION_NAME).build();
    }

    @Bean
    Exchange exchange() {
        return ExchangeBuilder.directExchange(RABBITMQ_DESTINATION_NAME).build();
    }

    @Bean
    Binding binding() {
        return BindingBuilder.bind(queue()).to(exchange()).with(RABBITMQ_DESTINATION_NAME).noargs();
    }

}
