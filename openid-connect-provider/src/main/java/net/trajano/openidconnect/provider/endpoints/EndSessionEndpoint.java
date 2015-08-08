package net.trajano.openidconnect.provider.endpoints;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.annotation.Annotation;
import java.net.URI;
import java.security.GeneralSecurityException;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.constraints.NotNull;
import javax.ws.rs.Consumes;
import javax.ws.rs.FormParam;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.ext.MessageBodyReader;
import javax.ws.rs.ext.Providers;

import net.trajano.openidconnect.core.ErrorCode;
import net.trajano.openidconnect.core.OpenIdConnectException;
import net.trajano.openidconnect.core.OpenIdConnectKey;
import net.trajano.openidconnect.crypto.JsonWebTokenProcessor;
import net.trajano.openidconnect.provider.spi.Authenticator;
import net.trajano.openidconnect.provider.spi.ClientManager;
import net.trajano.openidconnect.provider.spi.KeyProvider;
import net.trajano.openidconnect.provider.spi.TokenProvider;
import net.trajano.openidconnect.token.IdToken;

/**
 * An RP can notify the OP that the End-User has logged out of the site, and
 * might want to log out of the OP as well. In this case, the RP, after having
 * logged the End-User out of the RP, redirects the End-User's User Agent to the
 * OP's logout endpoint URL. This URL is normally obtained via the
 * end_session_endpoint element of the OP's Discovery response, or may be
 * learned via other mechanisms.
 *
 * @author Archimedes
 */
@Path("end")
@Stateless
@Produces(MediaType.APPLICATION_JSON)
public class EndSessionEndpoint {

    @EJB
    private Authenticator authenticator;

    @EJB
    private ClientManager clientManager;

    @EJB
    private KeyProvider keyProvider;

    @Context
    private Providers providers;

    @EJB
    private TokenProvider tokenProvider;

    /**
     * @param nonce
     *            nonce
     * @param logout
     *            if true then the session is terminated before the redirect
     * @param req
     * @return
     * @throws IOException
     * @throws GeneralSecurityException
     */
    @POST
    @Path("confirm")
    @Consumes(MediaType.APPLICATION_FORM_URLENCODED)
    public Response confirm(@NotNull @FormParam("nonce") final String nonce,
        @NotNull @FormParam("logout") final boolean logout,
        @Context final HttpServletRequest req) throws IOException,
            GeneralSecurityException {

        final HttpSession session = req.getSession(false);
        if (session == null || !session.getAttribute("nonce")
            .equals(nonce)) {
            throw new OpenIdConnectException(ErrorCode.access_denied);
        }

        final URI postLogoutRedirectUri = (URI) session.getAttribute("post_logout_redirect_uri");
        final String state = (String) session.getAttribute("state");
        if (logout) {
            authenticator.endSession(req);
            session.invalidate();
        }
        return Response.temporaryRedirect(UriBuilder.fromUri(postLogoutRedirectUri)
            .queryParam(OpenIdConnectKey.STATE, state)
            .build())
            .build();

    }

    /**
     * <p>
     * The Client sends the UserInfo Request using either HTTP GET or HTTP POST.
     * The Access Token obtained from an OpenID Connect Authentication Request
     * MUST be sent as a Bearer Token, per Section 2 of OAuth 2.0 Bearer Token
     * Usage [RFC6750].
     * </p>
     * <p>
     * It is RECOMMENDED that the request use the HTTP GET method and the Access
     * Token be sent using the Authorization header field.
     * </p>
     *
     * @param req
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     */
    @GET
    public Response getOp(@QueryParam("post_logout_redirect_uri") final URI postLogoutRedirectUri,
        @QueryParam(OpenIdConnectKey.ID_TOKEN_HINT) final String idTokenHint,
        @QueryParam(OpenIdConnectKey.STATE) final String state,
        @Context final HttpServletRequest req) throws IOException,
            GeneralSecurityException {

        return op(postLogoutRedirectUri, idTokenHint, state, req);
    }

    /**
     * <p>
     * This endpoint will store the needed logout information in the HTTP
     * session when available.
     * </p>
     * <p>
     * The <code>id_token_hint</code> is required by this implementation.
     * </p>
     *
     * @param postLogoutRedirectUri
     *            OPTIONAL. URL to which the RP is requesting that the
     *            End-User's User Agent be redirected after a logout has been
     *            performed. The value MUST have been previously registered with
     *            the OP, either using the post_logout_redirect_uris
     *            Registration parameter or via another mechanism. If supplied,
     *            the OP SHOULD honor this request following the logout.
     * @param idTokenHint
     *            RECOMMENDED. Previously issued ID Token passed to the logout
     *            endpoint as a hint about the End-User's current authenticated
     *            session with the Client. This is used as an indication of the
     *            identity of the End-User that the RP is requesting be logged
     *            out by the OP. The OP need not be listed as an audience of the
     *            ID Token when it is used as an id_token_hint value.
     * @param state
     *            OPTIONAL. Opaque value used by the RP to maintain state
     *            between the logout request and the callback to the endpoint
     *            specified by the post_logout_redirect_uri parameter. If
     *            included in the logout request, the OP passes this value back
     *            to the RP using the state query parameter when redirecting the
     *            User Agent back to the RP.
     * @param req
     * @return
     * @throws GeneralSecurityException
     * @throws IOException
     */
    @POST
    public Response op(@FormParam("post_logout_redirect_uri") final URI postLogoutRedirectUri,
        @FormParam(OpenIdConnectKey.ID_TOKEN_HINT) final String idTokenHint,
        @FormParam(OpenIdConnectKey.STATE) final String state,
        @Context final HttpServletRequest req) throws IOException,
            GeneralSecurityException {

        IdToken idToken = null;
        if (idTokenHint != null) {
            final JsonWebTokenProcessor idTokenProcessor = new JsonWebTokenProcessor(idTokenHint).jwks(keyProvider.getPrivateJwks());
            if (!idTokenProcessor.isJwkAvailable()) {
                throw new OpenIdConnectException(ErrorCode.invalid_request, "no jwk available for kid");
            }
            final byte[] idTokenBytes = idTokenProcessor.getPayload();
            final MessageBodyReader<IdToken> idTokenReader = providers.getMessageBodyReader(IdToken.class, IdToken.class, new Annotation[0], MediaType.APPLICATION_JSON_TYPE);
            idToken = idTokenReader.readFrom(IdToken.class, IdToken.class, new Annotation[0], MediaType.APPLICATION_JSON_TYPE, null, new ByteArrayInputStream(idTokenBytes));
        }
        if (postLogoutRedirectUri != null && idToken != null && !clientManager.isPostLogoutRedirectUriValidForClient(idToken.getAzp(), postLogoutRedirectUri)) {
            throw new OpenIdConnectException(ErrorCode.invalid_request);
        }

        final HttpSession session = req.getSession(false);
        if (session != null && authenticator.isAuthenticated(req)) {
            if (!authenticator.getSubject(req)
                .equals(idToken.getSub())) {
                throw new OpenIdConnectException(ErrorCode.access_denied);
            }
            final UriBuilder uriBuilder = UriBuilder.fromUri(req.getRequestURL()
                .toString())
                .replacePath(req.getContextPath());

            session.setAttribute("post_logout_redirect_uri", postLogoutRedirectUri);
            if (idToken != null) {
                session.setAttribute("id_token", idToken);
            }
            session.setAttribute("state", state);
            final String nonce = keyProvider.nextEncodedToken();
            session.setAttribute("nonce", nonce);

            return Response.temporaryRedirect(authenticator.logout(nonce, idToken, state, postLogoutRedirectUri, req, uriBuilder))
                .build();
        }
        // If the user is not authenticated, it just goes back to the post
        // redirect URI.
        return Response.temporaryRedirect(UriBuilder.fromUri(postLogoutRedirectUri)
            .queryParam(OpenIdConnectKey.STATE, state)
            .build())
            .build();

    }
}
