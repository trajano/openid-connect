package net.trajano.openidconnect.provider.spi;

import java.io.IOException;
import java.net.URI;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.auth.AuthenticationRequest;

public interface Authenticator {

    /**
     * <p>
     * Obtains the URI to the start of the authentication process. This must be
     * the full URL including the necessary query parameters.
     * </p>
     * <p>
     * The simplest way of doing this is to pass the "request" parameter that
     * encodes the original authentication request.
     * </p>
     * 
     * <pre>
     * return contextUriBuilder.path(&quot;login.jsp&quot;)
     *         .queryParam(OpenIdConnectKey.REQUEST, requestJwt)
     *         .build();
     * </pre>
     * <p>
     * Depending on some values on the authentication request such as "display"
     * or "ui-locale" a different URI can be provided.
     * </p>
     *
     * @param authenticationRequest
     *            authentication request
     * @param requestJwt
     *            the request encoded in a JWT
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
            String requestJwt,
            HttpServletRequest req,
            UriBuilder contextUri);

    /**
     * <p>
     * Checks if the user is authenticated.
     * </p>
     * <p>
     * If there is no UI application state for the OP aside, this will return
     * <code>false</code> to force the user to enter their credentials when
     * accessing the provider.
     * </p>
     *
     * @param authenticationRequest
     *            authentication request
     * @param req
     *            servlet request
     * @return <code>true</code> if the user is authenticated.
     * @throws IOException
     * @throws ServletException
     */
    boolean isAuthenticated(AuthenticationRequest authenticationRequest,
            HttpServletRequest req);

}
