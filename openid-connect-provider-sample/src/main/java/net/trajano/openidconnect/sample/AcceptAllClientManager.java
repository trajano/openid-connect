package net.trajano.openidconnect.sample;

import java.io.IOException;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.util.Set;

import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.core.Scope;
import net.trajano.openidconnect.core.TokenResponse;
import net.trajano.openidconnect.core.Userinfo;
import net.trajano.openidconnect.provider.AuthenticationRequest;
import net.trajano.openidconnect.provider.Authenticator;
import net.trajano.openidconnect.provider.ClientManager;
import net.trajano.openidconnect.provider.UserinfoProvider;

@Stateless
public class AcceptAllClientManager implements ClientManager, Authenticator, UserinfoProvider {

    @Override
    public boolean isRedirectUriValidForClient(String clientId,
            URI redirectUri) {

        return true;
    }

    @Override
    public boolean authenticateClient(String clientId,
            String clientSecret) {

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
                .build();
    }

    @Override
    public String getSubject(String clientId,
            HttpServletRequest req) {

        return null;
    }

    @Override
    public Userinfo getUserinfo(TokenResponse response) {

        Userinfo userinfo = new Userinfo();
        try {
            userinfo.setSub(response.getIdToken()
                    .getSub());
        } catch (IOException | GeneralSecurityException e) {
            throw new WebApplicationException(e);
        }
        return userinfo;
    }

    @Override
    public String getRealmName() {

        return "bearers";
    }

    @Override
    public Set<Scope> getScopes(String clientId,
            HttpServletRequest req) {

        // TODO Auto-generated method stub
        return null;
    }
}
