package net.trajano.openidconnect.provider.spi;

import javax.json.JsonObject;

import net.trajano.openidconnect.token.IdToken;
import net.trajano.openidconnect.token.IdTokenResponse;

/**
 * Provides storage for tokens used in the
 * 
 * @author Archimedes
 */
public interface TokenStorage {

    IdTokenResponse getByAccessToken(String accessToken);

    JsonObject getClaimsByAccessToken(String accessToken);

    /**
     * Gets the response by code.
     * 
     * @param code
     * @return
     */
    IdTokenResponse getByCode(String code);

    /**
     * Removes the mapping to the {@link IdTokenResponse} for a code.
     * 
     * @param code
     * @return the {@link IdTokenResponse} mapping that was removed.
     */
    IdTokenResponse removeMappingForCode(String code);

    /**
     * Removes the mapping to the {@link IdTokenResponse} for a refresh token.
     * 
     * @param refreshToken
     *            refresh token
     * @return the {@link IdTokenResponse} mapping that was removed.
     */
    IdTokenResponse removeMappingForRefreshToken(String refreshToken);

    /**
     * Removes the mapping to the {@link IdTokenResponse} for an access token.
     * 
     * @param accessToken
     *            access token
     * @return the {@link IdTokenResponse} mapping that was removed.
     */
    IdTokenResponse removeMappingForAccessToken(String accessToken);

    /**
     * Provides the expiration time for the tokens being provided. A desired
     * expiration can be provided, but the storage can decide to override it
     * with a different value.
     * 
     * @param desiredExpiration
     *            desired expiration time.
     * @return the expiration time of the token in seconds
     */
    int getExpiration(int desiredExpiration);

    /**
     * Provides the default expiration time for the tokens being provided when a
     * desired expiration is not provided.
     * 
     * @return the expiration time of the token in seconds
     */
    int getDefaultExpiration();

    /**
     * <p>
     * Store the token response in the storage.
     * </p>
     * <p>
     * It should use the {@link IdTokenResponse#getAccessToken()} and
     * {@link IdTokenResponse#getRefreshToken()} to store the mapping for the
     * access token and refresh token to the id token respectively. The
     * splitting up logic was not done in {@link TokenProvider} to allow
     * implementations of the {@link TokenStorage} that support composite key
     * building.
     * </p>
     * 
     * <pre>
     * accessTokenToTokenResponse.put(idTokenResponse.getAccessToken(), idTokenResponse);
     * refreshTokenToTokenResponse.put(idTokenResponse.getRefreshToken(), idTokenResponse);
     * Consent consent = new Consent(idToken, idTokenResponse);
     * subjectAndClientIdToTokenResponse.put(consent, idTokenResponse);
     * </pre>
     * 
     * @param idToken
     *            id token
     * @param idTokenResponse
     *            token response to store
     * @param claims
     *            claims requested
     */
    void store(IdToken idToken,
            IdTokenResponse idTokenResponse,
            JsonObject claims);

    /**
     * <p>
     * Store the token response in the storage and add a code mapping for it.
     * </p>
     * <p>
     * It should use the {@link IdTokenResponse#getAccessToken()} and
     * {@link IdTokenResponse#getRefreshToken()} to store the mapping for the
     * access token and refresh token to the id token respectively. The
     * splitting up logic was not done in {@link TokenProvider} to allow
     * implementations of the {@link TokenStorage} that support composite key
     * building.
     * </p>
     * <p>
     * This would generally call {@link #store(IdTokenResponse)} first followed
     * by storing the code mapping.
     * </p>
     * 
     * @param idToken
     *            id token
     * @param idTokenResponse
     *            token response to store
     * @param code
     *            code
     * @param claims
     *            claims requested
     */
    void store(IdToken idToken,
            IdTokenResponse idTokenResponse,
            String code,
            JsonObject claims);

    IdTokenResponse getByConsent(Consent consent);

    IdTokenResponse removeMappingForConsent(Consent consent);

    void markCodeAsUsed(String code);

    boolean isCodeUsed(String code);

}
