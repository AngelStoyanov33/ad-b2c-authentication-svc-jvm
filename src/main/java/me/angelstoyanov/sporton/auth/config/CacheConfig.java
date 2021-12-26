package me.angelstoyanov.sporton.auth.config;

import com.google.common.cache.CacheBuilder;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.Cache;
import org.springframework.cache.CacheManager;
import org.springframework.cache.annotation.EnableCaching;
import org.springframework.cache.concurrent.ConcurrentMapCache;
import org.springframework.cache.concurrent.ConcurrentMapCacheManager;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.concurrent.TimeUnit;

@Configuration
@EnableCaching
public class CacheConfig {

    @Value("${spring.security.oauth2.azure.ad.b2c.token.access.expiration.time}")
    private Integer cacheExpirationInMinutes;

    @Value("${spring.security.oauth2.azure.ad.b2c.token.caching.cache.size}")
    private Integer cacheSize;

    @Bean
    public CacheManager cacheManager() {
        return new ConcurrentMapCacheManager("tokens") {
            @Override
            protected Cache createConcurrentMapCache(final String name) {
                return new ConcurrentMapCache(name,
                        CacheBuilder
                                .newBuilder()
                                .expireAfterWrite(cacheExpirationInMinutes, TimeUnit.SECONDS)
                                .maximumSize(cacheSize)
                                .build().asMap(), false);
            }
        };
    }
}
