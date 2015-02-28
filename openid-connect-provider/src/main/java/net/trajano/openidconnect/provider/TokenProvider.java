package net.trajano.openidconnect.provider;

import net.trajano.openidconnect.core.IdToken;
import net.trajano.openidconnect.core.TokenResponse;

public interface TokenProvider {

    TokenResponse getByCode(String code);

    TokenResponse store(IdToken idToken);

    /**
     * Gets the token data by access token. This may return null if there is no
     * data found for the access token.
     * 
     * @param accessToken
     *            access token.
     * @return token response data
     */
    TokenResponse getByAccessToken(String accessToken);
}
