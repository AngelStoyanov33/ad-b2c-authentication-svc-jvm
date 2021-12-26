package me.angelstoyanov.sporton.auth.validation;

import org.springframework.security.oauth2.common.exceptions.InvalidTokenException;
import org.springframework.security.oauth2.provider.token.store.JwtClaimsSetVerifier;

import java.util.Map;


public class ClaimsValidator implements JwtClaimsSetVerifier {

    @Override
    public void verify(Map<String, Object> claims) throws InvalidTokenException {
        //TODO: implement
    }

    public ClaimsValidator(final String[] azureADAliases, final String[] acceptedTenants, final String applicationId) {
        //TODO: implement
    }
}
