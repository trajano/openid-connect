package net.trajano.openidconnect.provider;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.Response;

public interface Authenticator {

    /**
     * Checks if the user is authenticated.
     * 
     * @param req
     * @param resp
     * @return
     * @throws IOException
     * @throws ServletException
     */
    boolean isAuthenticated(AuthenticationRequest authenticationRequest,
            HttpServletRequest req);

    /**
     * Performs the authentication. For the most part this should be a redirect
     * to the login page.
     * 
     * @param req
     * @param resp
     * @return
     * @throws IOException
     * @throws ServletException
     */
    Response authenticate(AuthenticationRequest authenticationRequest,
            HttpServletRequest req);
}
