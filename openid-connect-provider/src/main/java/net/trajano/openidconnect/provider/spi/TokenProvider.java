package net.trajano.openidconnect.provider.spi;

import java.io.IOException;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.Set;

import javax.validation.constraints.NotNull;

import net.trajano.openidconnect.core.AuthenticationRequest;
import net.trajano.openidconnect.core.IdToken;
import net.trajano.openidconnect.core.IdTokenResponse;
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
     * Builds an {@link IdToken} for the subject . Extra implementation specific
     * options to the storage process to change certain aspects of the token can
     * be provided as well.
     *
     * @param subject
     *            subject
     * @return authorization code
     */
    IdToken buildIdToken(String subject,
            AuthenticationRequest request);

    Collection<IdTokenResponse> getAllTokenResponses();

    /**
     * Gets the token data by access token. This may return null if there is no
     * data found for the access token.
     *
     * @param accessToken
     *            access token.
     * @return token response data
     */
    IdTokenResponse getByAccessToken(String accessToken);

    /**
     * Gets the token by authorization code.
     *
     * @param code
     * @param deleteAfterRetrieval
     *            if true the implementation is expected to remove the code
     *            mapping to the token after the call
     * @return
     */
    IdTokenResponse getByCode(String code,
            boolean deleteAfterRetrieval);

    /**
     * @param clientId
     * @param refreshToken
     * @param scopes
     *            this may be null in which case the original scope is used, but
     *            can be used to reduce the scope after refresh.
     * @param expiresIn
     *            time in seconds of how long the new token will expire this
     *            will also reissue the ID token.
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     */
    TokenResponse refreshToken(@NotNull String clientId,
            @NotNull String refreshToken,
            Set<Scope> scopes,
            int expiresIn) throws IOException,
            GeneralSecurityException;

    /**
     * Stores the ID token and associated scope in some storage and creates the
     * access_token, authorization code and refresh token linkages.
     *
     * @param idToken
     *            idToken
     * @param req
     *            Authentication request
     * @return authorization code to retrieve the token data.
     * @throws IOException
     * @throws GeneralSecurityException
     */
    String store(IdToken idToken,
            AuthenticationRequest req) throws IOException,
            GeneralSecurityException;
}
