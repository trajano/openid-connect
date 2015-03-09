package net.trajano.openidconnect.sample;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Collection;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.ejb.EJB;
import javax.ejb.Lock;
import javax.ejb.LockType;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.core.Scope;
import net.trajano.openidconnect.provider.spi.Authenticator;
import net.trajano.openidconnect.provider.spi.ClientManager;
import net.trajano.openidconnect.provider.spi.KeyProvider;
import net.trajano.openidconnect.provider.spi.TokenProvider;
import net.trajano.openidconnect.provider.spi.UserinfoProvider;
import net.trajano.openidconnect.rs.IdTokenProvider;
import net.trajano.openidconnect.token.IdToken;
import net.trajano.openidconnect.token.IdTokenResponse;
import net.trajano.openidconnect.token.TokenResponse;
import net.trajano.openidconnect.userinfo.Userinfo;

// TODO move to a sample ejb package
@Singleton
@Startup
@Lock(LockType.READ)
public class AcceptAllClientManager implements ClientManager, Authenticator, UserinfoProvider, TokenProvider {

    private static final int ONE_HOUR = 120;

    private Map<String, IdTokenResponse> accessTokenToTokenResponse = new HashMap<>();

    public Map<String, IdTokenResponse> codeToTokenResponse = new HashMap<>();

    @EJB
    private KeyProvider keyProvider;

    private ConcurrentMap<String, IdTokenResponse> refreshTokenToTokenResponse = new ConcurrentHashMap<>();

    @Override
    public URI authenticate(final AuthenticationRequest authenticationRequest,
            String requestJwt,
            final HttpServletRequest req,
            final UriBuilder contextUriBuilder) {

        return contextUriBuilder.path("login.jsp")
                .queryParam(OpenIdConnectKey.REQUEST, requestJwt)
                .build();
    }

    @Override
    public String authenticateClient(final String clientId,
            final String clientSecret) {

        return clientId;
    }

    @Override
    public IdToken buildIdToken(final String subject,
            String issuer,
            final AuthenticationRequest req) {

        final IdToken idToken = new IdToken();
        idToken.setSub(subject);
        idToken.setNonce(req.getNonce());
        idToken.setAuthTime(System.currentTimeMillis() / 1000);
        idToken.setAud(req.getClientId());
        idToken.setAzp(req.getClientId());
        idToken.setIss(issuer);
        idToken.resetIssueAndExpiration(ONE_HOUR);
        return idToken;
    }

    @Override
    public Collection<IdTokenResponse> getAllTokenResponses() {

        return accessTokenToTokenResponse.values();
    }

    @Override
    public IdTokenResponse getByAccessToken(final String accessToken) {

        return accessTokenToTokenResponse.get(accessToken);
    }

    @Override
    @Lock(LockType.WRITE)
    public IdTokenResponse getByCode(final String code,
            final boolean deleteAfterRetrieval) {

        final IdTokenResponse tokenResponse = codeToTokenResponse.get(code);
        if (deleteAfterRetrieval) {
            codeToTokenResponse.remove(code);
        }
        return tokenResponse;
    }

    @Override
    public String getSubject(final String clientId,
            final HttpServletRequest req) {

        return null;
    }

    @Override
    public Userinfo getUserinfo(final IdTokenResponse response) {

        final Userinfo userinfo = new Userinfo();
        userinfo.setSub(response.getIdToken(keyProvider.getPrivateJwks())
                .getSub());
        userinfo.setUpdatedAt(new Date());
        return userinfo;
    }

    @Override
    public boolean isAuthenticated(final AuthenticationRequest authenticationRequest,
            final HttpServletRequest req) {

        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isRedirectUriValidForClient(final String clientId,
            final URI redirectUri) {

        return true;
    }

    @Override
    public IdTokenResponse refreshToken(final String clientId,
            final String refreshTokenIn,
            final Set<Scope> scopes,
            final Integer expiresIn) throws IOException,
            GeneralSecurityException {

        final IdTokenResponse idTokenResponse = refreshTokenToTokenResponse.remove(refreshTokenIn);
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
        accessTokenToTokenResponse.remove(idTokenResponse.getAccessToken());
        String newAccessToken = keyProvider.nextEncodedToken();
        String newRefreshToken = keyProvider.nextEncodedToken();

        idTokenResponse.setAccessToken(newAccessToken);
        idTokenResponse.setRefreshToken(newRefreshToken);
        final IdToken idToken = idTokenResponse.getIdToken(keyProvider.getJwks());
        if (expiresIn != null)
            idToken.resetIssueAndExpiration(expiresIn);
        else {
            idToken.resetIssueAndExpiration(ONE_HOUR);
        }

        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new IdTokenProvider().writeTo(idToken, IdToken.class, IdToken.class, null, MediaType.APPLICATION_JSON_TYPE, null, baos);
        baos.close();

        idTokenResponse.setEncodedIdToken(keyProvider.sign(baos.toByteArray()));

        accessTokenToTokenResponse.put(newAccessToken, idTokenResponse);
        refreshTokenToTokenResponse.put(newRefreshToken, idTokenResponse);

        return idTokenResponse;
    }

    @Override
    @Lock(LockType.WRITE)
    public String store(final IdToken idToken,
            final AuthenticationRequest req) throws IOException,
            GeneralSecurityException {

        final IdTokenResponse response = new IdTokenResponse();
        response.setAccessToken(keyProvider.nextEncodedToken());
        response.setRefreshToken(keyProvider.nextEncodedToken());
        response.setExpiresIn(ONE_HOUR);
        response.setScopes(req.getScopes());
        response.setTokenType(TokenResponse.BEARER);
        final ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new IdTokenProvider().writeTo(idToken, IdToken.class, IdToken.class, null, MediaType.APPLICATION_JSON_TYPE, null, baos);
        baos.close();
        response.setEncodedIdToken(keyProvider.sign(baos.toByteArray()));

        final String code = keyProvider.nextEncodedToken();
        codeToTokenResponse.put(code, response);
        accessTokenToTokenResponse.put(response.getAccessToken(), response);
        refreshTokenToTokenResponse.put(response.getRefreshToken(), response);

        return code;
    }
}
