package net.trajano.openidconnect.provider.endpoints;

import static net.trajano.openidconnect.core.ErrorCode.invalid_grant;
import static net.trajano.openidconnect.core.ErrorCode.login_required;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.ejb.EJB;
import javax.servlet.http.HttpServletRequest;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.UriBuilder;

import net.trajano.openidconnect.auth.AuthenticationRequest;
import net.trajano.openidconnect.auth.Prompt;
import net.trajano.openidconnect.core.ErrorResponse;
import net.trajano.openidconnect.core.OpenIdConnectException;
import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.core.RedirectedOpenIdProviderException;
import net.trajano.openidconnect.crypto.JsonWebTokenBuilder;
import net.trajano.openidconnect.provider.spi.Authenticator;
import net.trajano.openidconnect.provider.spi.ClientManager;
import net.trajano.openidconnect.provider.spi.KeyProvider;

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
public class AuthorizationEndpoint {

    private Authenticator authenticator;

    private KeyProvider keyProvider;

    private ClientManager clientManager;

    /**
     * <a href=
     * "https://localhost:8181/V1/auth?client_id=angelstone-client-id&scope=openid&state=170894&redirect_uri=https://www.getpostman.com/oauth2/callback&response_type=code"
     * >a</a>
     *
     * @param scope
     * @param req
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     */
    @GET
    public Response getOp(@Context final HttpServletRequest req) throws IOException,
            GeneralSecurityException {

        return op(req);
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
     * 
     * @throws GeneralSecurityException
     * @throws IOException
     */
    @POST
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response op(@Context final HttpServletRequest req) throws IOException,
            GeneralSecurityException {

        final AuthenticationRequest authenticationRequest = new AuthenticationRequest(req, keyProvider.getPrivateJwks());

        if (!clientManager.isRedirectUriValidForClient(authenticationRequest.getClientId(), authenticationRequest.getRedirectUri())) {
            throw new OpenIdConnectException(invalid_grant, "redirect URI is not supported for the client");
        }

        if (!authenticator.isAuthenticated(authenticationRequest, req) && authenticationRequest.getPrompts()
                .contains(Prompt.none)) {
            throw new RedirectedOpenIdProviderException(authenticationRequest, new ErrorResponse(login_required));
        }

        if (!authenticator.isAuthenticated(authenticationRequest, req)) {

            String reqJwt = req.getParameter(OpenIdConnectKey.REQUEST);
            if (reqJwt == null) {
                final JsonWebTokenBuilder b = new JsonWebTokenBuilder().payload(authenticationRequest.toJsonObject())
                        .compress(true);
                reqJwt = b.toString();
            }

            final UriBuilder uriBuilder = UriBuilder.fromUri(req.getRequestURL()
                    .toString())
                    .replacePath(req.getContextPath());
            return Response.temporaryRedirect(authenticator.authenticate(authenticationRequest, reqJwt, req, uriBuilder))
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

    @EJB
    public void setKeyProvider(final KeyProvider keyProvider) {

        this.keyProvider = keyProvider;
    }

}
