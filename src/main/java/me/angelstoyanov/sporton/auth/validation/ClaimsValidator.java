package me.angelstoyanov.sporton.auth.validation;

import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;

import java.lang.annotation.Native;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;


public class ClaimsValidator implements JwtClaimsSetVerifier {
    @Native
    private static final String AUD_CLAIM_NAME = "aud";

    @Native
    private static final String ISS_CLAIM_NAME = "iss";

    @Native
    private static final String AUD_PREFIX_V1 = "api://";

    @Native
    private static final String ISSUER_FORMAT_V2= "https://%s/%s/v2.0/";

    private final HashSet<String> acceptedIssuers;

    private final String applicationId;

    public ClaimsValidator(final String[] azureADAliases, final String[] acceptedTenants, final String applicationId) {
        this.acceptedIssuers = new HashSet<>();
        validateADAliasesAndTenants(azureADAliases, acceptedTenants);
        generateAcceptedIssuers(azureADAliases, acceptedTenants);

        Assert.notNull(applicationId, "Application ID cannot be null");
        this.applicationId = applicationId;

    }

    @Override
    public void verify(final Map<String, Object> claims) throws InvalidTokenException {
        if (CollectionUtils.isEmpty(claims)) {
            throw new InvalidTokenException("token must contain claims");
        }
        if (!claims.containsKey("aud")) {
            throw new InvalidTokenException("token must contain audience (aud) claim");
        }

        final String jwtIssuer = (String) claims.get(ISS_CLAIM_NAME);
        if (Arrays.stream(acceptedIssuers.toArray()).noneMatch(x -> x.equals(jwtIssuer))) {
            throw new InvalidTokenException("Invalid Issuer (iss) claim: " + jwtIssuer);
        }

        final String jwtAud = (String) claims.get(AUD_CLAIM_NAME);
        if (!jwtAud.equals(applicationId) && !jwtAud.equals(AUD_PREFIX_V1 + applicationId)) {
            throw new InvalidTokenException("Invalid Audience (aud) claim: " + jwtAud);
        }

    }

    private void validateADAliasesAndTenants(final String[] azureADAliases, final String[] acceptedTenants) {
        Assert.notEmpty(azureADAliases, "Azure AD Aliases cannot be empty");
        for (final String issuer : azureADAliases) {
            Assert.notNull(issuer, "An Azure AD Alias cannot be null");
        }

        Assert.notEmpty(acceptedTenants, "Accepted Tenants cannot be empty");
        for (final String tenant : acceptedTenants) {
            Assert.notNull(tenant, "An Accepted Tenant cannot be null");
        }
    }

    private void generateAcceptedIssuers(final String[] azureADAliases, final String[] acceptedTenants) {
        for (String issuer : azureADAliases) {
            for (String acceptedTenant : acceptedTenants) {
                acceptedIssuers.add(String.format(ISSUER_FORMAT_V2, issuer, acceptedTenant));
            }
        }
    }

}
