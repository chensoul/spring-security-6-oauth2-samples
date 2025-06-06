package com.chensoul.keys;

import java.time.Instant;
import org.springframework.context.ApplicationEvent;

public class RsaKeyParGenerationRequestEvent extends ApplicationEvent {

	public RsaKeyParGenerationRequestEvent(Instant instant) {
		super(instant);
	}

	@Override
	public Instant getSource() {
		return (Instant) super.getSource();
	}

}