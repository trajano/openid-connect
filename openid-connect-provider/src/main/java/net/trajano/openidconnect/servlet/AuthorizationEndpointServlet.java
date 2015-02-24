package net.trajano.openidconnect.servlet;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.core.AuthenticationErrorResponseParam;
import net.trajano.openidconnect.core.AuthenticationErrorResponseParam.ErrorCode;
import net.trajano.openidconnect.core.AuthenticationRequestParam;
import net.trajano.openidconnect.servlet.internal.AuthenticationRequest;

/**
 * <p>
 * The Authorization Endpoint performs Authentication of the End-User. This is
 * done by sending the User Agent to the Authorization Server's Authorization
 * Endpoint for Authentication and Authorization, using request parameters
 * defined by OAuth 2.0 and additional parameters and parameter values defined
 * by OpenID Connect.
 * </p>
 * <p>
 * Communication with the Authorization Endpoint MUST utilize TLS. See Section
 * 16.17 for more information on using TLS.
 * </p>
 *
 * @author Archimedes
 */
public abstract class AuthorizationEndpointServlet extends HttpServlet {

    /**
     *
     */
    private static final long serialVersionUID = 4255947522328618454L;

    private ClientManager clientManager;

    private void createError(final AuthenticationRequest authenticationRequest,
            final HttpServletResponse resp,
            final ErrorCode errorCode,
            final String errorDescription) throws IOException {

        final UriBuilder errorUri = UriBuilder.fromUri(authenticationRequest.getRedirectUri())
                .queryParam(AuthenticationErrorResponseParam.ERROR, errorCode);
        if (errorDescription != null) {
            errorUri.queryParam(AuthenticationErrorResponseParam.ERROR_DESCRIPTION, errorDescription);
        }
        if (authenticationRequest.getState() != null) {
            errorUri.queryParam(AuthenticationErrorResponseParam.STATE, errorDescription);
        }
        resp.sendRedirect(errorUri.build()
                .toASCIIString());
    }

    @Override
    protected void doGet(final HttpServletRequest req,
            final HttpServletResponse resp) throws ServletException,
            IOException {

        doPost(req, resp);
    }

    /**
     * <p>
     * An Authentication Request is an OAuth 2.0 Authorization Request that
     * requests that the End-User be authenticated by the Authorization Server.
     * </p>
     * <p>
     * Authorization Servers MUST support the use of the HTTP GET and POST
     * methods defined in RFC 2616 [RFC2616] at the Authorization Endpoint.
     * Clients MAY use the HTTP GET or POST methods to send the Authorization
     * Request to the Authorization Server. If using the HTTP GET method, the
     * request parameters are serialized using URI Query String Serialization,
     * per Section 13.1. If using the HTTP POST method, the request parameters
     * are serialized using Form Serialization, per Section 13.2.
     * </p>
     */
    @Override
    protected void doPost(final HttpServletRequest req,
            final HttpServletResponse resp) throws ServletException,
            IOException {

        final AuthenticationRequest authenticationRequest = new AuthenticationRequest(req);

        if (!clientManager.isRedirectUriValidForClient(authenticationRequest.getClientId(), authenticationRequest.getRedirectUri())) {
            throw new ServletException("redirect URI is not supported for the client");
        }

        if (!req.isSecure()) {
            createError(authenticationRequest, resp, AuthenticationErrorResponseParam.ErrorCode.invalid_request, "secure connection required");
            return;
        }

        if (!authenticationRequest.getScopes()
                .contains("openid")) {
            createError(authenticationRequest, resp, AuthenticationErrorResponseParam.ErrorCode.invalid_request, "the request must contain the 'openid' scope value");
            return;
        }

        if (authenticationRequest.getPrompts()
                .contains(AuthenticationRequestParam.Prompt.none) && authenticationRequest.getPrompts()
                .size() != 1) {
            createError(authenticationRequest, resp, AuthenticationErrorResponseParam.ErrorCode.invalid_request, "Cannot have 'none' with any other value for 'prompt'");
            return;
        }

        if (!isAuthenticated(authenticationRequest, req, resp) && authenticationRequest.getPrompts()
                .contains(AuthenticationRequestParam.Prompt.none)) {
            createError(authenticationRequest, resp, AuthenticationErrorResponseParam.ErrorCode.login_required, null);
            return;
        }
    }

    /**
     * Checks if the user is authenticated.
     * 
     * @param req
     * @param resp
     * @return
     * @throws IOException
     * @throws ServletException
     */
    protected abstract boolean isAuthenticated(AuthenticationRequest authenticationRequest,
            HttpServletRequest req,
            HttpServletResponse resp) throws IOException,
            ServletException;

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
    protected abstract void authenticate(AuthenticationRequest authenticationRequest,
            HttpServletRequest req,
            HttpServletResponse resp) throws IOException,
            ServletException;

    @Override
    public void init() throws ServletException {

        clientManager = buildClientManager();
    }

    /**
     * A client manager must be provided by the classes that extend this. The
     * method is only invoked on {@link #init()}.
     * 
     * @return
     * @throws ServletException
     */
    protected abstract ClientManager buildClientManager() throws ServletException;
}
