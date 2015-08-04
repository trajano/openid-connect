package net.trajano.openidconnect.provider.sample;

import java.io.StringReader;
import java.util.HashSet;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.ejb.Lock;
import javax.ejb.LockType;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.json.Json;
import javax.json.JsonObject;

import net.trajano.openidconnect.provider.spi.Consent;
import net.trajano.openidconnect.provider.spi.TokenStorage;
import net.trajano.openidconnect.token.IdToken;
import net.trajano.openidconnect.token.IdTokenResponse;

/**
 * An implementation of {@link TokenStorage} as a set of {@link ConcurrentMap}s.
 * Normally a real implementation would use JCache based backend with expiration
 * otherwise there would be memory issues.
 *
 * @author Archimedes
 */
@Singleton
@Startup
public class MapTokenStorage implements
    TokenStorage {

    private static final int ONE_HOUR = 120;

    private final ConcurrentMap<String, String> accessTokenToClaims = new ConcurrentHashMap<>();

    private final ConcurrentMap<String, IdTokenResponse> accessTokenToTokenResponse = new ConcurrentHashMap<>();

    private final ConcurrentMap<String, IdTokenResponse> codeToTokenResponse = new ConcurrentHashMap<>();

    private final ConcurrentMap<Consent, IdTokenResponse> consentToTokenResponse = new ConcurrentHashMap<>();

    private final ConcurrentMap<String, IdTokenResponse> refreshTokenToTokenResponse = new ConcurrentHashMap<>();

    private final Set<String> usedCodes = new HashSet<>();

    @Override
    public IdTokenResponse getByAccessToken(final String accessToken) {

        return accessTokenToTokenResponse.get(accessToken);
    }

    @Override
    public IdTokenResponse getByCode(final String code) {

        return codeToTokenResponse.get(code);
    }

    @Override
    public IdTokenResponse getByConsent(final Consent consent) {

        return consentToTokenResponse.get(consent);
    }

    @Override
    public JsonObject getClaimsByAccessToken(final String accessToken) {

        return Json.createReader(new StringReader(accessTokenToClaims.get(accessToken)))
            .readObject();
    }

    @Override
    public int getDefaultExpiration() {

        return ONE_HOUR;
    }

    @Override
    public int getExpiration(final int desiredExpiration) {

        return desiredExpiration;
    }

    @Override
    public boolean isCodeUsed(final String code) {

        return usedCodes.contains(code);
    }

    @Override
    public void markCodeAsUsed(final String code) {

        usedCodes.add(code);
    }

    @Override
    @Lock(LockType.WRITE)
    public IdTokenResponse removeMappingForAccessToken(final String accessToken) {

        accessTokenToClaims.remove(accessToken);
        return accessTokenToTokenResponse.remove(accessToken);
    }

    @Override
    @Lock(LockType.WRITE)
    public IdTokenResponse removeMappingForCode(final String code) {

        return codeToTokenResponse.remove(code);
    }

    @Override
    @Lock(LockType.WRITE)
    public IdTokenResponse removeMappingForConsent(final Consent consent) {

        return consentToTokenResponse.remove(consent);

    }

    @Override
    @Lock(LockType.WRITE)
    public IdTokenResponse removeMappingForRefreshToken(final String refreshToken) {

        return refreshTokenToTokenResponse.remove(refreshToken);

    }

    @Lock(LockType.WRITE)
    @Override
    public void store(final IdToken idToken,
        final IdTokenResponse idTokenResponse,
        final JsonObject claims) {

        accessTokenToTokenResponse.put(idTokenResponse.getAccessToken(), idTokenResponse);
        accessTokenToClaims.put(idTokenResponse.getAccessToken(), claims.toString());
        refreshTokenToTokenResponse.put(idTokenResponse.getRefreshToken(), idTokenResponse);
        consentToTokenResponse.put(new Consent(idToken, idTokenResponse), idTokenResponse);
    }

    @Lock(LockType.WRITE)
    @Override
    public void store(final IdToken idToken,
        final IdTokenResponse idTokenResponse,
        final String code,
        final JsonObject claims) {

        // TODO create a proper class for claims rather than using a JsonObject.
        store(idToken, idTokenResponse, claims);
        codeToTokenResponse.put(code, idTokenResponse);

    }
}
