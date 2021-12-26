package me.angelstoyanov.sporton.auth.config;

import me.angelstoyanov.sporton.auth.validation.ClaimsValidator;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;
import org.springframework.security.oauth2.provider.token.store.jwk.JwkTokenStore;

import java.lang.annotation.Native;

@Configuration
public class ResourceServerConfig extends ResourceServerConfigurerAdapter {

    @Value("${spring.security.oauth2.resource.jwk.key-set-uri}")
    private String keysetUri;

    @Value("${spring.security.oauth2.client.client-id}")
    private String applicationId;

    @Value("${spring.security.oauth2.accepted.tenants}")
    private String[] acceptedTenants;

    @Value("${spring.security.oauth2.scope.access-as-user}")
    private String accessAsUserScope;

    @Value("${spring.security.oauth2.azure.ad.b2c.aliases}")
    private String[] azureADAliases;

    @Value("${spring.security.oauth2.azure.ad.b2c.scope.claim.name}")
    private String AZURE_AD_SCOPE_CLAIM;

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/*")
                .authenticated();
    }
    @Bean
    public JwtAccessTokenConverter accessTokenConverter() {
        JwtAccessTokenConverter jwtConverter = new JwtAccessTokenConverter();

        DefaultAccessTokenConverter accessTokenConverter = new DefaultAccessTokenConverter();
        accessTokenConverter.setScopeAttribute(AZURE_AD_SCOPE_CLAIM);

        jwtConverter.setAccessTokenConverter(accessTokenConverter);

        return jwtConverter;
    }

    @Bean
    public JwtClaimsSetVerifier claimSetVerifier() {
        return new ClaimsValidator(azureADAliases, acceptedTenants, applicationId);
    }

    @Bean
    public TokenStore tokenStore() {
        return new JwkTokenStore(keysetUri, accessTokenConverter(), claimSetVerifier());
    }

}
