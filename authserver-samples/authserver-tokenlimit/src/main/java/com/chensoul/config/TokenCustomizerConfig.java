package com.chensoul.config;

import com.chensoul.tokenlimit.AccessTokenLimiter;
import com.chensoul.tokenlimit.AccessTokenRestrictionCustomizer;
import com.chensoul.tokenlimit.RedisAccessTokenLimiter;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

/**
 * TODO Comment
 *
 * @author <a href="mailto:ichensoul@gmail.com">chensoul</a>
 * @since TODO
 */
@Configuration
public class TokenCustomizerConfig {
    @Bean
    @ConditionalOnClass(RedisTemplate.class)
    public AccessTokenLimiter tokenLimiter(RedisTemplate redisTemplate, RedisScript script) {
        return new RedisAccessTokenLimiter(redisTemplate, script);
    }

    @Bean
    @ConditionalOnClass(AccessTokenLimiter.class)
    public OAuth2TokenCustomizer<JwtEncodingContext> tokenCustomizer(AccessTokenLimiter tokenLimiter) {
        return new AccessTokenRestrictionCustomizer(tokenLimiter);
    }
}
