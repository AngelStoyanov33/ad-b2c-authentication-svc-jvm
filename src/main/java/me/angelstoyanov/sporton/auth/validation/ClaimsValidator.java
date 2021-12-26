package me.angelstoyanov.sporton.auth.validation;

import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.lang.annotation.Native;
import java.util.HashSet;
import java.util.Map;


public class ClaimsValidator implements JwtClaimsSetVerifier {

    @Native
    private static final String AUD_CLAIM_NAME = "aud";

    @Native
    private static final String AUD_PREFIX_V1 = "api://";
    
    private final String applicationId;

    @Override
    public void verify(final Map<String, Object> claims) throws InvalidTokenException {
        if (CollectionUtils.isEmpty(claims)) {
            throw new InvalidTokenException("token must contain claims");
        }
        if (!claims.containsKey("aud")) {
            throw new InvalidTokenException("token must contain audience (aud) claim");
        }
        final String jwtAud = (String) claims.get(AUD_CLAIM_NAME);
        if (!jwtAud.equals(applicationId) && !jwtAud.equals(AUD_PREFIX_V1 + applicationId)) {
            throw new InvalidTokenException("Invalid Audience (aud) claim: " + jwtAud);
        }

    }

    public ClaimsValidator(final String[] azureADAliases, final String[] acceptedTenants, final String applicationId) {
        validateADAliasesAndTenants(azureADAliases, acceptedTenants);

        Assert.notNull(applicationId, "Application ID cannot be null");
        this.applicationId = applicationId;
    }

    private void validateADAliasesAndTenants(final String[] azureADAliases, final String[] acceptedTenants){
        Assert.notEmpty(azureADAliases, "Azure AD Aliases cannot be empty");
        for (final String issuer : azureADAliases) {
            Assert.notNull(issuer, "An Azure AD Alias cannot be null");
        }

        Assert.notEmpty(acceptedTenants, "Accepted Tenants cannot be empty");
        for (final String tenant : acceptedTenants) {
            Assert.notNull(tenant, "An Accepted Tenant cannot be null");
        }
    }

}
