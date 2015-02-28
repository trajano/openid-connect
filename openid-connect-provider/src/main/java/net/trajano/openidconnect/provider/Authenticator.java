package net.trajano.openidconnect.provider;

import java.io.IOException;
import java.net.URI;
import java.util.Set;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.core.Scope;

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
     * Obtains the URI to the start of the authentication process.
     * 
     * @param authenticationRequest
     *            authentication request
     * @param req
     *            servlet request
     * @param contextUriBuilder
     *            {@link UriBuilder} pointing to the context.
     * @return
     * @throws IOException
     * @throws ServletException
     */
    URI authenticate(AuthenticationRequest authenticationRequest,
            HttpServletRequest req,
            UriBuilder contextUri);

    /**
     * Obtains the subject for the current user. Depending on the client ID the
     * user obtained in the request may not be valid. May return
     * <code>null</code> if the subject cannot be determined.
     * 
     * @param clientId
     *            client ID
     * @param req
     * @return
     */
    String getSubject(String clientId,
            HttpServletRequest req);

    /**
     * Obtains the scopes requested for the current user. Depending on the client ID the
     * user obtained in the request may not be valid. May return
     * <code>null</code> if the subject cannot be determined.
     * 
     * @param clientId
     *            client ID
     * @param req
     * @return
     */
    Set<Scope> getScopes(String clientId,
            HttpServletRequest req);
}
