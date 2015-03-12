package net.trajano.openidconnect.sample;

import java.net.URI;
import java.util.Date;

import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.provider.spi.Authenticator;
import net.trajano.openidconnect.provider.spi.ClientManager;
import net.trajano.openidconnect.provider.spi.UserinfoProvider;
import net.trajano.openidconnect.token.IdToken;
import net.trajano.openidconnect.userinfo.Userinfo;

@Stateless
public class AcceptAllClientManager implements ClientManager, Authenticator, UserinfoProvider {

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
    public Userinfo getUserinfo(final IdToken idToken) {

        final Userinfo userinfo = new Userinfo();
        userinfo.setSub(idToken.getSub());
        userinfo.setUpdatedAt(new Date());
        return userinfo;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean isAuthenticated(final AuthenticationRequest authenticationRequest,
            final HttpServletRequest req) {

        return req.getSession().getAttribute("sub") != null;
    }

    @Override
    public boolean isRedirectUriValidForClient(final String clientId,
            final URI redirectUri) {

        return true;
    }
}
