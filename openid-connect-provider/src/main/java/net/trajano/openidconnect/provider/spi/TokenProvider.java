package net.trajano.openidconnect.provider.spi;

import java.util.Set;

import net.trajano.openidconnect.core.IdToken;
import net.trajano.openidconnect.core.Scope;
import net.trajano.openidconnect.core.TokenResponse;

/**
 * This provides storage and retrieval for the token responses. Implementers
 * would generally be providing an expiring cache that provides multiple key
 * types pointing to the same token response instance.
 * 
 * @author Archimedes
 */
public interface TokenProvider {

    /**
     * Gets the token by authorization code.
     * 
     * @param code
     * @param deleteAfterRetrieval
     *            if true the implementation is expected to remove the code
     *            mapping to the token after the call
     * @return
     */
    TokenResponse getByCode(String code,
            boolean deleteAfterRetrieval);

    /**
     * Stores the ID token and associated scope in some storage and creates the
     * access_token, authorization code and refresh token linkages.
     * 
     * @param idToken
     *            idToken
     * @param scope
     *            scopes requested
     * @return authorization code to retrieve the token data.
     */
    String store(IdToken idToken,
            Set<Scope> scopes);

    /**
     * Builds an {@link IdToken} for the subject . Extra implementation specific
     * options to the storage process to change certain aspects of the token can
     * be provided as well.
     * 
     * @param subject
     *            subject
     * @param extraOptions
     *            extra options
     * @return authorization code
     */
    IdToken buildIdToken(String subject,
            Object... extraOptions);

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
