package me.angelstoyanov.sporton.auth.component;

import com.google.common.hash.Hashing;
import com.microsoft.aad.msal4j.*;
import com.microsoft.graph.authentication.BaseAuthenticationProvider;
import me.angelstoyanov.sporton.auth.exception.AuthenticationException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.CacheManager;
import org.springframework.context.annotation.Scope;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.provider.authentication.OAuth2AuthenticationDetails;
import org.springframework.stereotype.Component;
import org.springframework.util.Assert;

import javax.annotation.Nonnull;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.concurrent.CompletableFuture;

@Component
@Scope("application")
public class AuthenticationProvider extends BaseAuthenticationProvider {

    @Value("${spring.security.oauth2.client.authority}")
    private String authorityUri;

    @Value("${spring.security.oauth2.client.client-id}")
    private String clientId;

    @Value("${spring.security.oauth2.client.client-secret}")
    private String clientSecret;

    @Value("${spring.security.azure.ad.graph.scope.default}")
    private String graphScope;

    @Value("${spring.security.oauth2.azure.ad.b2c.token.caching.cache.collection.name}")
    private String cacheCollectionName;

    @Autowired(required = true)
    CacheManager cacheManager;

    private String getAccessTokenFromRequest() {
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        if (authentication != null) {
            return ((OAuth2AuthenticationDetails) authentication.getDetails()).getTokenValue();
        }
        return null;
    }

    @Nonnull
    @Override
    public CompletableFuture<String> getAuthorizationTokenAsync(@Nonnull URL url) {
        String authenticationToken = this.getAccessTokenFromRequest();
        Assert.notNull(authenticationToken, "Authentication token cannot be null");
        String cacheKey = Hashing.sha512().hashString(authenticationToken, StandardCharsets.UTF_8).toString();

        IAuthenticationResult authResult;
        ConfidentialClientApplication application;
        try {
            application = ConfidentialClientApplication
                    .builder(clientId, ClientCredentialFactory.createFromSecret(clientSecret))
                    .authority(authorityUri)
                    .build();

            String cachedTokens = cacheManager.getCache(cacheCollectionName).get(cacheKey, String.class);
            if (cachedTokens != null) {
                application.tokenCache().deserialize(cachedTokens);
            }

            OnBehalfOfParameters parameters = OnBehalfOfParameters.builder(Collections.singleton(graphScope),
                    new UserAssertion(authenticationToken)).build();

            authResult = application.acquireToken(parameters).join();

        } catch (Exception ex) {
            throw new AuthenticationException(String.format("Error acquiring token from Azure AD B2C -> [%s]", ex.getMessage()), ex.getCause());
        }

        cacheManager.getCache(cacheCollectionName).put(cacheKey, application.tokenCache().serialize());
        return CompletableFuture.completedFuture(authResult.accessToken());
    }
}
