package net.trajano.openidconnect.sample;

import java.net.URI;
import java.util.Date;
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

@Singleton
@Startup
@Lock(LockType.READ)
public class AcceptAllClientManager implements ClientManager, Authenticator, UserinfoProvider, TokenStorage {

    private static final int ONE_HOUR = 120;

    private ConcurrentMap<String, IdTokenResponse> accessTokenToTokenResponse = new ConcurrentHashMap<>();

    public ConcurrentMap<String, IdTokenResponse> codeToTokenResponse = new ConcurrentHashMap<>();

    @EJB
    private KeyProvider keyProvider;

    private ConcurrentMap<String, IdTokenResponse> refreshTokenToTokenResponse = new ConcurrentHashMap<>();

    @Override
    public URI authenticate(final AuthenticationRequest authenticationRequest,
            final String requestJwt,
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
    public IdTokenResponse getByCode(final String code) {

        return codeToTokenResponse.get(code);
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
    public Userinfo getUserinfo(final IdTokenResponse response) {

        final Userinfo userinfo = new Userinfo();
        userinfo.setSub(response.getIdToken(keyProvider.getPrivateJwks())
                .getSub());
        userinfo.setUpdatedAt(new Date());
        return userinfo;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Since there is no UI application for the provider aside from the login
     * screen, this will return <code>false</code> to force the user to enter
     * their credentials when accessing the provider.</o>
     *
     * @return <code>false</code>
     */
    @Override
    public boolean isAuthenticated(final AuthenticationRequest authenticationRequest,
            final HttpServletRequest req) {

        return false;
    }

    @Override
    public boolean isRedirectUriValidForClient(final String clientId,
            final URI redirectUri) {

        return true;
    }

    @Override
    @Lock(LockType.WRITE)
    public IdTokenResponse removeMappingForAccessToken(final String accessToken) {

        return accessTokenToTokenResponse.remove(accessToken);
    }

    @Override
    @Lock(LockType.WRITE)
    public IdTokenResponse removeMappingForCode(final String code) {

        return codeToTokenResponse.remove(code);
    }

    @Override
    @Lock(LockType.WRITE)
    public IdTokenResponse removeMappingForRefreshToken(final String refreshToken) {

        return refreshTokenToTokenResponse.remove(refreshToken);

    }

    @Lock(LockType.WRITE)
    @Override
    public void store(final IdTokenResponse idTokenResponse) {

        accessTokenToTokenResponse.put(idTokenResponse.getAccessToken(), idTokenResponse);
        refreshTokenToTokenResponse.put(idTokenResponse.getRefreshToken(), idTokenResponse);
    }

    @Lock(LockType.WRITE)
    @Override
    public void store(final IdTokenResponse idTokenResponse,
            final String code) {

        store(idTokenResponse);
        codeToTokenResponse.put(code, idTokenResponse);

    }
}
