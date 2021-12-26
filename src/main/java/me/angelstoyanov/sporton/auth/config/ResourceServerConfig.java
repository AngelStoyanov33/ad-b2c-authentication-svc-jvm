package me.angelstoyanov.sporton.auth.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.config.annotation.web.configuration.ResourceServerConfigurerAdapter;

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

    @Override
    public void configure(HttpSecurity http) throws Exception {
        http.sessionManagement()
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                .and()
                .authorizeRequests()
                .antMatchers("/*")
                .authenticated();
    }

}
