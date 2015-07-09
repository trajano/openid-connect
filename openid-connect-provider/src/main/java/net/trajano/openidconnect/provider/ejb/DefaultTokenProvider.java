package net.trajano.openidconnect.provider.ejb;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Map.Entry;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.json.JsonObject;
import javax.json.JsonValue;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.core.Scope;
import net.trajano.openidconnect.crypto.Encoding;
import net.trajano.openidconnect.crypto.JsonWebAlgorithm;
import net.trajano.openidconnect.crypto.JsonWebTokenBuilder;
import net.trajano.openidconnect.internal.CharSets;
import net.trajano.openidconnect.provider.spi.Consent;
import net.trajano.openidconnect.provider.spi.KeyProvider;
import net.trajano.openidconnect.provider.spi.TokenProvider;
import net.trajano.openidconnect.provider.spi.TokenStorage;
import net.trajano.openidconnect.provider.spi.UserinfoProvider;
import net.trajano.openidconnect.rs.IdTokenProvider;
import net.trajano.openidconnect.token.IdToken;
import net.trajano.openidconnect.token.IdTokenResponse;
import net.trajano.openidconnect.token.TokenResponse;
import net.trajano.openidconnect.userinfo.Userinfo;

@Stateless
public class DefaultTokenProvider implements TokenProvider {

    @EJB
    private KeyProvider keyProvider;

    @EJB
    private TokenStorage tokenStorage;

    @EJB
    private UserinfoProvider userinfoProvider;

    /**
     * Calculates the hash for the token. Primarily for at_hash value.
     *
     * @param token
     * @return
     * @throws GeneralSecurityException
     */
    private String computeHash(final String token) throws GeneralSecurityException {

        // TODO this should be based on something.
        final MessageDigest digest = MessageDigest.getInstance("SHA-256");
        final byte[] digestedBytes = digest.digest(token.getBytes(CharSets.US_ASCII));

        return Encoding.base64urlEncode(digestedBytes, 0, 128 / 8);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String createNewToken(final String subject,
            final URI issuer,
            final AuthenticationRequest req) throws IOException,
                    GeneralSecurityException {

        final IdToken idToken = new IdToken();
        idToken.setSub(subject);
        idToken.setNonce(req.getNonce());
        idToken.setAuthTime(System.currentTimeMillis() / 1000);
        idToken.setAud(req.getClientId());
        idToken.setAzp(req.getClientId());
        idToken.setIss(issuer.toASCIIString());
        idToken.setAcr("0");

        if (req.getClaims()
                .containsKey("id_token")) {
            Userinfo userinfo = userinfoProvider.getUserinfo(idToken);
            for (Entry<String, JsonValue> e : req.getClaims()
                    .getJsonObject("id_token")
                    .entrySet()) {
                if ("name".equals(e.getKey())) {
                    idToken.setName(userinfo.getName());
                }
            }
        }

        return store(idToken, req);
    }

    @Override
    public IdTokenResponse getByAccessToken(final String accessToken) {

        return tokenStorage.getByAccessToken(accessToken);
    }

    @Override
    public IdTokenResponse getByCode(final String code,
            final boolean deleteAfterRetrieval) {

        final IdTokenResponse tokenResponse = tokenStorage.getByCode(code);

        if (tokenStorage.isCodeUsed(code)) {
            // Revoke access tokens since code was used twice.
            tokenStorage.removeMappingForAccessToken(tokenResponse.getAccessToken());
            tokenStorage.removeMappingForRefreshToken(tokenResponse.getRefreshToken());
            tokenStorage.removeMappingForCode(code);
            return null;
        }
        if (deleteAfterRetrieval) {
            tokenStorage.markCodeAsUsed(code);
        }
        return tokenResponse;
    }

    @Override
    public IdTokenResponse getByConsent(final Consent consent) {

        return tokenStorage.getByConsent(consent);
    }

    @Override
    public IdTokenResponse refreshToken(final String clientId,
            final String refreshTokenIn,
            final Set<Scope> scopes,
            final Integer expiresIn) throws IOException,
                    GeneralSecurityException {

        final IdTokenResponse idTokenResponse = tokenStorage.removeMappingForRefreshToken(refreshTokenIn);
        if (!clientId.equals(idTokenResponse.getIdToken(keyProvider.getPrivateJwks())
                .getAud())) {
            throw new WebApplicationException();
        }
        if (scopes != null && !scopes.containsAll(scopes)) {
            throw new WebApplicationException();
        }
        if (scopes != null && scopes.containsAll(scopes)) {
            idTokenResponse.setScopes(scopes);
        }

        JsonObject claims = tokenStorage.getClaimsByAccessToken(idTokenResponse.getAccessToken());
        // remove from map we are getting a new one
        tokenStorage.removeMappingForAccessToken(idTokenResponse.getAccessToken());
        final String newAccessToken = keyProvider.nextEncodedToken();
        final String newRefreshToken = keyProvider.nextEncodedToken();

        idTokenResponse.setAccessToken(newAccessToken);
        idTokenResponse.setRefreshToken(newRefreshToken);
        final IdToken idToken = idTokenResponse.getIdToken(keyProvider.getJwks());

        if (expiresIn != null) {
            idToken.resetIssueAndExpiration(tokenStorage.getExpiration(expiresIn));
        } else {
            idToken.resetIssueAndExpiration(tokenStorage.getDefaultExpiration());
        }

        idToken.setAtHash(computeHash(newAccessToken));

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new IdTokenProvider().writeTo(idToken, IdToken.class, IdToken.class, null, MediaType.APPLICATION_JSON_TYPE, null, baos);
        baos.close();

        final JsonWebTokenBuilder jwtBuilder = new JsonWebTokenBuilder().jwk(keyProvider.getPrivateJwks())
                .payload(baos.toByteArray());
        idTokenResponse.setEncodedIdToken(jwtBuilder.toString());

        tokenStorage.store(idToken, idTokenResponse, claims);

        return idTokenResponse;
    }

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
    private String store(final IdToken idToken,
            final AuthenticationRequest req) throws IOException,
                    GeneralSecurityException {

        final IdTokenResponse response = new IdTokenResponse();
        final String newAccessToken = keyProvider.nextEncodedToken();
        response.setAccessToken(newAccessToken);
        response.setRefreshToken(keyProvider.nextEncodedToken());
        response.setExpiresIn(tokenStorage.getDefaultExpiration());
        response.setScopes(req.getScopes());
        response.setTokenType(TokenResponse.BEARER);

        idToken.setAtHash(computeHash(newAccessToken));

        final String code = keyProvider.nextEncodedToken();
        idToken.setCHash(computeHash(code));
        
        idToken.resetIssueAndExpiration(tokenStorage.getDefaultExpiration());

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new IdTokenProvider().writeTo(idToken, IdToken.class, IdToken.class, null, MediaType.APPLICATION_JSON_TYPE, null, baos);
        baos.close();
        final JsonWebTokenBuilder jwtBuilder = new JsonWebTokenBuilder().jwk(keyProvider.getPrivateJwks())
                .alg(JsonWebAlgorithm.RS256)
                .payload(baos.toByteArray());
        response.setEncodedIdToken(jwtBuilder.toString());

        tokenStorage.store(idToken, response, code, req.getClaims());

        return code;
    }

    @Override
    public JsonObject getClaimsByAccessToken(String accessToken) {

        return tokenStorage.getClaimsByAccessToken(accessToken);
    }

}
