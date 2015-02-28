package net.trajano.openidconnect.provider;

import java.net.URI;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.core.AuthenticationErrorResponseParam;
import net.trajano.openidconnect.core.AuthenticationErrorResponseParam.ErrorCode;
import net.trajano.openidconnect.core.AuthenticationRequestParam;
import net.trajano.openidconnect.core.Scope;

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
@Path("auth")
@Stateless
public class AuthorizationEndpoint {

    private Authenticator authenticator;

    private ClientManager clientManager;

    private Response createError(final AuthenticationRequest authenticationRequest,
            final ErrorCode errorCode,
            final String errorDescription) {

        final UriBuilder errorUri = UriBuilder.fromUri(authenticationRequest.getRedirectUri())
                .queryParam(AuthenticationErrorResponseParam.ERROR, errorCode);
        if (errorDescription != null) {
            errorUri.queryParam(AuthenticationErrorResponseParam.ERROR_DESCRIPTION, errorDescription);
        }
        if (authenticationRequest.getState() != null) {
            errorUri.queryParam(AuthenticationErrorResponseParam.STATE, errorDescription);
        }
        return Response.temporaryRedirect(errorUri.build())
                .build();
    }

    /**
     * <a href=
     * "https://localhost:8181/V1/auth?client_id=angelstone-client-id&scope=openid&state=170894&redirect_uri=https://www.getpostman.com/oauth2/callback&response_type=code"
     * >a</a>
     *
     * @param scope
     * @param req
     * @return
     */
    @GET
    public Response getOp(@QueryParam(AuthenticationRequestParam.SCOPE) @NotNull final String scope,
            @QueryParam(AuthenticationRequestParam.CLIENT_ID) @NotNull final String clientId,
            @QueryParam(AuthenticationRequestParam.REDIRECT_URI) @NotNull final URI redirectUri,
            @Context final HttpServletRequest req) {

        return op(scope, clientId, redirectUri, req);
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
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response op(@FormParam(AuthenticationRequestParam.SCOPE) @NotNull final String scope,
            @FormParam(AuthenticationRequestParam.CLIENT_ID) @NotNull final String clientId,
            @FormParam(AuthenticationRequestParam.REDIRECT_URI) @NotNull final URI redirectUri,
            @Context final HttpServletRequest req) {

        final AuthenticationRequest authenticationRequest = new AuthenticationRequest(req);
        System.out.println("here" + authenticator + " " + clientManager);

        if (!clientManager.isRedirectUriValidForClient(authenticationRequest.getClientId(), authenticationRequest.getRedirectUri())) {
            throw new WebApplicationException("redirect URI is not supported for the client", Status.BAD_REQUEST);
        }

        if (!req.isSecure()) {
            return createError(authenticationRequest, AuthenticationErrorResponseParam.ErrorCode.invalid_request, "secure connection required");
        }

        if (!authenticationRequest.getScopes()
                .contains(Scope.openid)) {
            return createError(authenticationRequest, AuthenticationErrorResponseParam.ErrorCode.invalid_request, "the request must contain the 'openid' scope value");
        }

        if (authenticationRequest.getPrompts()
                .contains(AuthenticationRequestParam.Prompt.none) && authenticationRequest.getPrompts()
                .size() != 1) {
            return createError(authenticationRequest, AuthenticationErrorResponseParam.ErrorCode.invalid_request, "Cannot have 'none' with any other value for 'prompt'");

        }

        if (!authenticator.isAuthenticated(authenticationRequest, req) && authenticationRequest.getPrompts()
                .contains(AuthenticationRequestParam.Prompt.none)) {
            return createError(authenticationRequest, AuthenticationErrorResponseParam.ErrorCode.login_required, null);
        }

        if (!authenticator.isAuthenticated(authenticationRequest, req)) {
            return Response.temporaryRedirect(authenticator.authenticate(authenticationRequest, req, UriBuilder.fromUri(req.getRequestURL()
                    .toString())
                    .replacePath(req.getContextPath())))
                    .build();
        }

        throw new WebApplicationException(Status.BAD_REQUEST);

    }

    @EJB
    public void setAuthenticator(final Authenticator authenticator) {

        this.authenticator = authenticator;
    }

    @EJB
    public void setClientManager(final ClientManager clientManager) {

        this.clientManager = clientManager;
    }

}
