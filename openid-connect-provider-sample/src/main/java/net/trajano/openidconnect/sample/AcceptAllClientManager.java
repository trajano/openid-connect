package net.trajano.openidconnect.sample;

import java.net.URI;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.ejb.EJB;
import javax.ejb.Lock;
import javax.ejb.LockType;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.provider.spi.Authenticator;
import net.trajano.openidconnect.provider.spi.ClientManager;
import net.trajano.openidconnect.provider.spi.KeyProvider;
import net.trajano.openidconnect.provider.spi.TokenStorage;
import net.trajano.openidconnect.provider.spi.UserinfoProvider;
import net.trajano.openidconnect.token.IdTokenResponse;
import net.trajano.openidconnect.userinfo.Userinfo;

// TODO move to a sample ejb package
@Singleton
@Startup
@Lock(LockType.READ)
public class AcceptAllClientManager implements ClientManager, Authenticator, UserinfoProvider, TokenStorage {

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
    public IdTokenResponse getByAccessToken(final String accessToken) {

        return accessTokenToTokenResponse.get(accessToken);
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
    public IdTokenResponse getByCode(String code) {

        return codeToTokenResponse.get(code);
    }

    @Override
    public IdTokenResponse removeMappingForCode(String code) {

        return codeToTokenResponse.remove(code);
    }

    @Override
    public IdTokenResponse removeMappingForRefreshToken(String refreshToken) {

        return refreshTokenToTokenResponse.remove(refreshToken);

    }

    @Override
    public IdTokenResponse removeMappingForAccessToken(String accessToken) {

        return accessTokenToTokenResponse.remove(accessToken);
    }

    @Override
    public int getExpiration(int desiredExpiration) {

        return desiredExpiration;
    }

    @Override
    public int getDefaultExpiration() {

        return ONE_HOUR;
    }

    @Override
    public void store(IdTokenResponse idTokenResponse) {

        accessTokenToTokenResponse.put(idTokenResponse.getAccessToken(), idTokenResponse);
        refreshTokenToTokenResponse.put(idTokenResponse.getRefreshToken(), idTokenResponse);
    }

    @Override
    public void store(IdTokenResponse idTokenResponse,
            String code) {

        accessTokenToTokenResponse.put(idTokenResponse.getAccessToken(), idTokenResponse);
        refreshTokenToTokenResponse.put(idTokenResponse.getRefreshToken(), idTokenResponse);
        codeToTokenResponse.put(code, idTokenResponse);

    }
}
