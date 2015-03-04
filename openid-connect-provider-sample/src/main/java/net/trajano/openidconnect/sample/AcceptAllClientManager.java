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
import net.trajano.openidconnect.auth.AuthenticationRequestParam;
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

    private static final int ONE_HOUR = 3600;

    @Override
    public boolean isRedirectUriValidForClient(String clientId,
            URI redirectUri) {

        return true;
    }

    @Override
    public boolean isAuthenticated(AuthenticationRequest authenticationRequest,
            HttpServletRequest req) {

        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public URI authenticate(AuthenticationRequest authenticationRequest,
            HttpServletRequest req,
            UriBuilder contextUriBuilder) {

        return contextUriBuilder.path("login.jsp")
                .queryParam(AuthenticationRequestParam.CLIENT_ID, authenticationRequest.getClientId())
                .queryParam(AuthenticationRequestParam.REDIRECT_URI, authenticationRequest.getRedirectUri())
                .queryParam(AuthenticationRequestParam.SCOPE, authenticationRequest.getScope())
                .queryParam(AuthenticationRequestParam.RESPONSE_TYPE, authenticationRequest.getResponseType())
                .queryParam(AuthenticationRequestParam.STATE, authenticationRequest.getState())
                .queryParam(AuthenticationRequestParam.NONCE, authenticationRequest.getNonce())
                .queryParam(AuthenticationRequestParam.RESPONSE_MODE, authenticationRequest.getResponseMode())
                .build();
    }

    @Override
    public String getSubject(String clientId,
            HttpServletRequest req) {

        return null;
    }

    @Override
    public Userinfo getUserinfo(IdTokenResponse response) {

        Userinfo userinfo = new Userinfo();
        userinfo.setSub(response.getIdToken()
                .getSub());
        userinfo.setUpdatedAt(new Date());
        return userinfo;
    }

    @Override
    public URI getIssuer() {

        return URI.create("https://helloworld");
    }

    @Override
    @Lock(LockType.WRITE)
    public IdTokenResponse getByCode(String code,
            boolean deleteAfterRetrieval) {

        IdTokenResponse tokenResponse = codeToTokenResponse.get(code);
        if (deleteAfterRetrieval) {
            codeToTokenResponse.remove(code);
        }
        return tokenResponse;
    }

    @Override
    @Lock(LockType.WRITE)
    public String store(IdToken idToken,
            AuthenticationRequest req) throws IOException,
            GeneralSecurityException {

        IdTokenResponse response = new IdTokenResponse();
        response.setAccessToken(keyProvider.nextEncodedToken());
        response.setRefreshToken(keyProvider.nextEncodedToken());
        response.setExpiresIn(ONE_HOUR);
        response.setScopes(req.getScopes());
        response.setTokenType(IdTokenResponse.BEARER);
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new IdTokenProvider().writeTo(idToken, IdToken.class, IdToken.class, null, MediaType.APPLICATION_JSON_TYPE, null, baos);
        baos.close();
        response.setEncodedIdToken(keyProvider.sign(baos.toByteArray()));

        String code = keyProvider.nextEncodedToken();
        codeToTokenResponse.put(code, response);
        accessTokenToTokenResponse.put(response.getAccessToken(), response);
        refreshTokenToTokenResponse.put(response.getRefreshToken(), response);


        return code;
    }

    public Map<String, IdTokenResponse> codeToTokenResponse = new HashMap<>();

    private Map<String, IdTokenResponse> accessTokenToTokenResponse = new HashMap<>();

    private Map<String, IdTokenResponse> refreshTokenToTokenResponse = new HashMap<>();

    @Override
    public IdToken buildIdToken(String subject,
            AuthenticationRequest req) {

        IdToken idToken = new IdToken();
        idToken.setSub(subject);
        idToken.setNonce(req.getNonce());
        idToken.setAuthTime(System.currentTimeMillis() / 1000);
        idToken.setAud(req.getClientId());
        idToken.setAzp(req.getClientId());
        idToken.setIss(getIssuer().toASCIIString());
        idToken.resetIssueAndExpiration(ONE_HOUR);
        return idToken;
    }

    @Override
    public IdTokenResponse getByAccessToken(String accessToken) {

        return accessTokenToTokenResponse.get(accessToken);
    }

    @EJB
    KeyProvider keyProvider;

    @Override
    public TokenResponse refreshToken(String clientId,
            String token,
            Set<Scope> scopes,
            int expiresIn) throws IOException,
            GeneralSecurityException {

        IdTokenResponse idTokenResponse = refreshTokenToTokenResponse.get(token);
        if (!clientId.equals(idTokenResponse.getIdToken()
                .getAud())) {
            throw new WebApplicationException();
        }
        if (scopes != null && !scopes.containsAll(scopes)) {
            throw new WebApplicationException();
        }
        if (scopes != null && scopes.containsAll(scopes)) {
            idTokenResponse.setScopes(scopes);
        }
        idTokenResponse.setAccessToken(keyProvider.nextEncodedToken());
        IdToken idToken = idTokenResponse.getIdToken(keyProvider.getJwks());
        idToken.resetIssueAndExpiration(expiresIn);

        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        new IdTokenProvider().writeTo(idToken, IdToken.class, IdToken.class, null, MediaType.APPLICATION_JSON_TYPE, null, baos);
        baos.close();

        idTokenResponse.setEncodedIdToken(keyProvider.sign(baos.toByteArray()));

        TokenResponse response = new TokenResponse();
        response.setAccessToken(idTokenResponse.getAccessToken());
        response.setExpiresIn(expiresIn);
        return null;
    }

    @Override
    public Collection<IdTokenResponse> getAllTokenResponses() {

        return accessTokenToTokenResponse.values();
    }

    @Override
    public String authenticateClient(String clientId,
            String clientSecret) {

        return clientId;
    }
}
