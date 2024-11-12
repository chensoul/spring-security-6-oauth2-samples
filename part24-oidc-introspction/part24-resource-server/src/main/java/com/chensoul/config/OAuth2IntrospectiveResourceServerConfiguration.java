package com.chensoul.config;

import com.chensoul.introspection.CachingOAuth2IntrospectionService;
import com.chensoul.introspection.JdbcOAuth2IntrospectionService;
import com.chensoul.introspection.OAuth2Introspection;
import com.chensoul.introspection.OAuth2IntrospectionService;
import com.github.benmanes.caffeine.cache.Caffeine;
import java.time.Duration;
import java.util.Collections;
import java.util.UUID;
import java.util.concurrent.TimeUnit;
import org.springframework.cache.CacheManager;
import org.springframework.cache.caffeine.CaffeineCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.cache.RedisCacheConfiguration;
import org.springframework.data.redis.cache.RedisCacheManager;
import org.springframework.data.redis.connection.RedisConnectionFactory;
import org.springframework.data.redis.serializer.GenericJackson2JsonRedisSerializer;
import org.springframework.data.redis.serializer.RedisSerializationContext;
import org.springframework.data.redis.serializer.StringRedisSerializer;
import org.springframework.jdbc.core.JdbcTemplate;

@Configuration(proxyBeanMethods = false)
public class OAuth2IntrospectiveResourceServerConfiguration {

    @Bean
    public CacheManager cacheManager() {
        CaffeineCacheManager cacheManager = new CaffeineCacheManager();
        cacheManager.setCaffeine(Caffeine.newBuilder()
                .initialCapacity(100)
                .maximumSize(200)
                .expireAfterWrite(10, TimeUnit.MINUTES)
                .recordStats());
        return cacheManager;
    }

    @Bean
    public OAuth2IntrospectionService oAuth2IntrospectionService(RedisConnectionFactory redisConnectionFactory,
                                                                 JdbcTemplate jdbcTemplate) {
        RedisCacheConfiguration defaultCacheConfig = RedisCacheConfiguration.defaultCacheConfig()
                // 设置key为string序列化
                .serializeKeysWith(RedisSerializationContext.SerializationPair.fromSerializer(new StringRedisSerializer()))
                // 设置value为json序列化
                .serializeValuesWith(RedisSerializationContext.SerializationPair.fromSerializer(new GenericJackson2JsonRedisSerializer()))
                // 不缓存空值
                .disableCachingNullValues()
                // 设置缓存过期时间
                .entryTtl(Duration.ofMinutes(5));

        RedisCacheManager cacheManager = RedisCacheManager.builder(redisConnectionFactory)
                .cacheDefaults(defaultCacheConfig)
                .initialCacheNames(Collections.singleton("oauth2Introspection"))
                .build();

        OAuth2IntrospectionService oAuth2IntrospectionService = new CachingOAuth2IntrospectionService(cacheManager.getCache("oauth2Introspection"), new JdbcOAuth2IntrospectionService(jdbcTemplate));

        oAuth2IntrospectionService.saveOAuth2Introspection(OAuth2Introspection.withIssuer("http://auth-server:9000")
                .id(UUID.randomUUID().toString())
                .clientId("client")
                .clientSecret("client")
                .introspectionUri("http://auth-server:9000/oauth2/introspect").build());
        return oAuth2IntrospectionService;
    }
}