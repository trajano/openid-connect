package net.trajano.openidconnect.provider.ejb;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Set;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.core.Scope;
import net.trajano.openidconnect.crypto.JsonWebAlgorithm;
import net.trajano.openidconnect.crypto.JsonWebTokenBuilder;
import net.trajano.openidconnect.provider.spi.KeyProvider;
import net.trajano.openidconnect.provider.spi.SubjectAndClientId;
import net.trajano.openidconnect.provider.spi.TokenProvider;
import net.trajano.openidconnect.provider.spi.TokenStorage;
import net.trajano.openidconnect.rs.IdTokenProvider;
import net.trajano.openidconnect.token.IdToken;
import net.trajano.openidconnect.token.IdTokenResponse;
import net.trajano.openidconnect.token.TokenResponse;

@Stateless
public class DefaultTokenProvider implements TokenProvider {

    @EJB
    KeyProvider keyProvider;

    @EJB
    private TokenStorage tokenStorage;

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
        idToken.resetIssueAndExpiration(tokenStorage.getDefaultExpiration());

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
        if (deleteAfterRetrieval) {
            tokenStorage.removeMappingForCode(code);
        }
        return tokenResponse;
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

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new IdTokenProvider().writeTo(idToken, IdToken.class, IdToken.class, null, MediaType.APPLICATION_JSON_TYPE, null, baos);
        baos.close();

        final JsonWebTokenBuilder jwtBuilder = new JsonWebTokenBuilder().jwk(keyProvider.getPrivateJwks())
                .payload(baos.toByteArray());
        idTokenResponse.setEncodedIdToken(jwtBuilder.toString());

        tokenStorage.store(idToken, idTokenResponse);

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
        response.setAccessToken(keyProvider.nextEncodedToken());
        response.setRefreshToken(keyProvider.nextEncodedToken());
        response.setExpiresIn(tokenStorage.getDefaultExpiration());
        response.setScopes(req.getScopes());
        response.setTokenType(TokenResponse.BEARER);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new IdTokenProvider().writeTo(idToken, IdToken.class, IdToken.class, null, MediaType.APPLICATION_JSON_TYPE, null, baos);
        baos.close();
        final JsonWebTokenBuilder jwtBuilder = new JsonWebTokenBuilder().jwk(keyProvider.getPrivateJwks())
                .alg(JsonWebAlgorithm.RS256)
                .payload(baos.toByteArray());
        response.setEncodedIdToken(jwtBuilder.toString());

        final String code = keyProvider.nextEncodedToken();
        tokenStorage.store(idToken, response, code);

        return code;
    }

    @Override
    public IdTokenResponse getBySubjectAndClientId(String subject,
            String clientId) {

        return tokenStorage.getBySubjectAndClientId(new SubjectAndClientId(subject, clientId));
    }

}
