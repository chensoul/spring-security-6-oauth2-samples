
package com.chensoul.config;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import org.springframework.lang.Nullable;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContext;
import org.springframework.security.oauth2.server.authorization.context.AuthorizationServerContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

@Component
public class TenantPerIssuerComponentRegistry {
	private final ConcurrentMap<String, Map<Class<?>, Object>> registry = new ConcurrentHashMap<>();

	public <T> void register(String tenantId, Class<T> componentClass, T component) {
		Assert.hasText(tenantId, "tenantId cannot be empty");
		Assert.notNull(componentClass, "componentClass cannot be null");
		Assert.notNull(component, "component cannot be null");
		Map<Class<?>, Object> components = this.registry.computeIfAbsent(tenantId, (key) -> new ConcurrentHashMap<>());
		components.put(componentClass, component);
	}

	@Nullable
	public <T> T get(Class<T> componentClass) {
		AuthorizationServerContext context = AuthorizationServerContextHolder.getContext();
		if (context == null || context.getIssuer() == null) {
			return null;
		}
		for (Map.Entry<String, Map<Class<?>, Object>> entry : this.registry.entrySet()) {
			if (context.getIssuer().endsWith(entry.getKey())) {
				return componentClass.cast(entry.getValue().get(componentClass));
			}
		}
		return null;
	}
}