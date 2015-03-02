package net.trajano.openidconnect.provider.spi;

import java.io.IOException;
import java.net.URI;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.core.AuthenticationRequest;

public interface Authenticator {

    /**
     * Obtains the URI to the start of the authentication process. This must be
     * the full URL including the necessary query parameters.
     * <p>
     * The simplest way of doing this is to pass the query parameters that are
     * needed as-is, but it is recommended that the request data be encoded and
     * passed as a single query parameter to reduce the amount of parameters
     * that need to be passed
     * </p>
     *
     * @param authenticationRequest
     *            authentication request
     * @param req
     *            servlet request
     * @param contextUriBuilder
     *            {@link UriBuilder} pointing to the context. The rest can be
     *            added on from there.
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

}
