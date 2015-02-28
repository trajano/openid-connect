package net.trajano.openidconnect.sample;

import java.net.URI;

import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;

import net.trajano.openidconnect.provider.AuthenticationRequest;
import net.trajano.openidconnect.provider.Authenticator;
import net.trajano.openidconnect.provider.ClientManager;

@Stateless
public class AcceptAllClientManager implements ClientManager, Authenticator {

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
    public Response authenticate(AuthenticationRequest authenticationRequest,
            HttpServletRequest req) {

        // TODO Auto-generated method stub
        return null;
    }

}
